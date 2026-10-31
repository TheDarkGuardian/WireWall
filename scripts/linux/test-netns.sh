#!/usr/bin/env bash
# Creates an isolated pair of namespaces; never attaches to the host uplink.
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.."
[[ $EUID -eq 0 ]] || { echo "Run in an Ubuntu lab VM as root." >&2; exit 1; }
for dependency in ip python3 curl; do command -v "$dependency" >/dev/null || { echo "Missing: $dependency" >&2; exit 1; }; done
[[ -x bin/wirewall && -f bpf/wirewall_bpfel.o ]] || { echo "Build WireWall first." >&2; exit 1; }

client="ww-client-$$"
server="ww-server-$$"
client_link="wwc-$$"
server_link="wws-$$"
client_created=0
server_created=0
veth_created=0
temporary=$(mktemp -d /tmp/wirewall-netns-XXXXXX)
firewall_pid=
service_pid=
denied_service_pid=
cleanup() {
  [[ -z "$firewall_pid" ]] || kill "$firewall_pid" 2>/dev/null || true
  if [[ -n "$firewall_pid" ]]; then
    for attempt in $(seq 1 50); do
      kill -0 "$firewall_pid" 2>/dev/null || break
      sleep 0.1
    done
  fi
  [[ -z "$service_pid" ]] || kill "$service_pid" 2>/dev/null || true
  [[ -z "$denied_service_pid" ]] || kill "$denied_service_pid" 2>/dev/null || true
  # Clean only namespaces created by this invocation. A pre-existing namespace
  # with a reused PID suffix must never be removed after a failed `netns add`.
  if [[ "$server_created" -eq 1 ]]; then
    while read -r namespace_pid; do
      [[ -z "$namespace_pid" ]] || kill "$namespace_pid" 2>/dev/null || true
    done < <(ip netns pids "$server" 2>/dev/null)
    ip netns del "$server" 2>/dev/null || true
  fi
  [[ "$client_created" -eq 0 ]] || ip netns del "$client" 2>/dev/null || true
  if [[ "$veth_created" -eq 1 ]] && ip link show dev "$client_link" >/dev/null 2>&1; then
    ip link del dev "$client_link" 2>/dev/null || true
  fi
  resolved=$(realpath -- "$temporary")
  case "$resolved" in /tmp/wirewall-netns-*) rm -rf -- "$resolved" ;; esac
}
trap cleanup EXIT INT TERM

ip netns add "$client"
client_created=1
ip netns add "$server"
server_created=1
ip link add "$client_link" type veth peer name "$server_link"
veth_created=1
ip link set "$client_link" netns "$client"
ip link set "$server_link" netns "$server"
ip -n "$client" link set "$client_link" name ww-client
ip -n "$server" link set "$server_link" name ww-server
ip -n "$client" link set lo up
ip -n "$server" link set lo up
ip -n "$client" address add 192.0.2.2/24 dev ww-client
ip -n "$server" address add 192.0.2.1/24 dev ww-server
ip -n "$client" link set ww-client up
ip -n "$server" link set ww-server up

cat >"$temporary/policy.json" <<'JSON'
{
  "version":1,"mode":"enforce","interface":"ww-server","xdpMode":"generic",
  "managementCidrs":["192.0.2.2/32"],"managementPort":22,
  "host":{"tcpPorts":[8080],"udpPorts":[],"ipv6":false},
  "rules":[{"id":"deny8081","name":"test deny","enabled":true,"priority":10,
    "action":"drop","protocol":"tcp","source":"any","destination":"any",
    "sourcePort":"any","destinationPort":"8081","minPacketBytes":0,"maxPacketBytes":0,"pps":0,"burst":0}]
}
JSON

ip netns exec "$server" python3 -m http.server 8080 --bind 192.0.2.1 >"$temporary/service.log" 2>&1 &
service_pid=$!
ip netns exec "$server" python3 -m http.server 8081 --bind 192.0.2.1 >"$temporary/denied-service.log" 2>&1 &
denied_service_pid=$!

# Establish both services are actually listening before the firewall starts.
baseline=0
for attempt in $(seq 1 30); do
  if ip netns exec "$client" curl --silent --fail --max-time 1 http://192.0.2.1:8080/ >/dev/null && \
     ip netns exec "$client" curl --silent --fail --max-time 1 http://192.0.2.1:8081/ >/dev/null; then baseline=1; break; fi
  sleep 0.2
done
[[ "$baseline" -eq 1 ]] || { echo "Baseline services are not both reachable" >&2; exit 1; }

# Confirm the exact startup flags in docs/LINUX.md for the current binary. The
# independent rollback guard is part of the normal xdp startup path.
ip netns exec "$server" "$PWD/bin/wirewall" serve --backend xdp \
  --confirm-network-changes --object "$PWD/bpf/wirewall_bpfel.o" \
  --policy "$temporary/policy.json" --data "$temporary" --listen 127.0.0.1:9876 \
  >"$temporary/firewall.log" 2>&1 &
firewall_pid=$!

ready=0
for attempt in $(seq 1 60); do
  if ! kill -0 "$firewall_pid" 2>/dev/null; then cat "$temporary/firewall.log" >&2; exit 1; fi
  if ip netns exec "$server" curl --silent --fail --noproxy '*' --max-time 1 http://127.0.0.1:9876/api/v1/health >/dev/null; then ready=1; break; fi
  sleep 0.5
done
[[ "$ready" -eq 1 ]] || { cat "$temporary/firewall.log" >&2; echo "XDP startup did not become healthy" >&2; exit 1; }
operator_token=$(cat "$temporary/operator.token")
ip netns exec "$server" curl --silent --fail --noproxy '*' --max-time 2 \
  -H "Authorization: Bearer $operator_token" -H 'Content-Type: application/json' \
  -X POST -d '{}' http://127.0.0.1:9876/api/v1/policy/confirm >/dev/null
ip netns exec "$client" curl --silent --fail --noproxy '*' --max-time 2 http://192.0.2.1:8080/ >/dev/null
if ip netns exec "$client" curl --silent --noproxy '*' --max-time 1 http://192.0.2.1:8081/ >/dev/null; then
  echo "Denied port unexpectedly succeeded" >&2; exit 1
fi
counted=0
for attempt in $(seq 1 10); do
  ip netns exec "$server" curl --silent --fail --noproxy '*' --max-time 2 \
    -H "Authorization: Bearer $operator_token" \
    http://127.0.0.1:9876/api/v1/snapshot >"$temporary/snapshot.json"
  if python3 - "$temporary/snapshot.json" <<'PY'
import json, sys
with open(sys.argv[1], encoding="utf-8") as stream:
    snapshot = json.load(stream)
assert any(reason["reason"] == "rule_drop" and reason["count"] > 0
           for reason in snapshot["metrics"]["reasons"]), "XDP rule_drop counter has not advanced"
PY
  then counted=1; break; fi
  sleep 0.5
done
[[ "$counted" -eq 1 ]] || { echo "Connection was blocked, but the XDP rule_drop counter did not prove the cause" >&2; exit 1; }
echo "Namespace smoke passed: allowed service reachable, denied service not reachable."
echo "The unsampled XDP rule_drop counter also advanced."

wait_guards() {
  for attempt in $(seq 1 50); do
    if python3 - "$server" <<'PY'
import pathlib,subprocess,sys
for pid in subprocess.check_output(['ip','netns','pids',sys.argv[1]],text=True).split():
 try: raw=pathlib.Path('/proc/'+pid+'/cmdline').read_bytes()
 except FileNotFoundError: continue
 if b'rollback-guard' in raw:sys.exit(1)
PY
    then return; fi
    sleep 0.1
  done
  echo 'Previous watchdog has not released ownership' >&2; exit 1
}

# Confirmed deployment continuity is opt-in; a changed policy must still arm
# a new watchdog. All confirmations here refer only to disposable namespaces.
kill "$firewall_pid"
wait "$firewall_pid" || true
firewall_pid=
wait_guards
agent_socket="$temporary/run/control.sock"
start_agent() {
  ip netns exec "$server" "$PWD/bin/wirewall" agent --confirm-network-changes \
    --resume-confirmed --policy "$temporary/policy.json" --object "$PWD/bpf/wirewall_bpfel.o" \
    --data "$temporary/agent-data" --socket "$agent_socket" "$@" >"$temporary/agent.log" 2>&1 &
  firewall_pid=$!
  for attempt in $(seq 1 60); do
    kill -0 "$firewall_pid" 2>/dev/null || { cat "$temporary/agent.log" >&2; exit 1; }
    if curl --silent --fail --unix-socket "$agent_socket" http://localhost/api/v1/snapshot >"$temporary/ready-snapshot.json" 2>/dev/null && \
      python3 -c 'import json,sys; sys.exit(0 if json.load(open(sys.argv[1]))["system"]["attached"] else 1)' "$temporary/ready-snapshot.json"; then return; fi
    sleep 0.2
  done
  echo 'Agent readiness timeout' >&2; exit 1
}
assert_pending() {
  curl --silent --fail --unix-socket "$agent_socket" http://localhost/api/v1/snapshot >"$temporary/agent-snapshot.json"
  python3 - "$temporary/agent-snapshot.json" "$1" <<'PY'
import json,sys
data=json.load(open(sys.argv[1]));assert data['system']['activationPending']==(sys.argv[2]=='true'), data['system']
assert data['system']['attached']
assert data['metrics']['hostFirewall']['available'], data['metrics']['hostFirewall']
PY
}
start_agent
assert_pending true
ip netns exec "$client" curl --silent --fail --max-time 2 http://192.0.2.1:8080/ >/dev/null
curl --silent --fail --unix-socket "$agent_socket" -X POST http://localhost/api/v1/policy/confirm >/dev/null
kill "$firewall_pid"; wait "$firewall_pid" || true; firewall_pid=; wait_guards
start_agent
assert_pending false
ip netns exec "$client" curl --silent --fail --max-time 2 http://192.0.2.1:8080/ >/dev/null
kill "$firewall_pid"; wait "$firewall_pid" || true; firewall_pid=; wait_guards
python3 - "$temporary/policy.json" <<'PY'
import json,sys
path=sys.argv[1];data=json.load(open(path));data['mode']='observe'
with open(path,'w') as stream:json.dump(data,stream)
PY
start_agent --replace-policy
assert_pending true
echo 'Confirmed startup continuity passed; changed policy still requires confirmation.'
