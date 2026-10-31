#!/usr/bin/env bash
# Real watchdog/crash regression in disposable namespaces; never uses an uplink.
set -euo pipefail
if [[ $- == *x* ]]; then
  set +x
  echo "Do not run recovery tests with shell tracing enabled." >&2
  exit 1
fi
cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.."
[[ $EUID -eq 0 ]] || { echo "Run in an Ubuntu lab VM as root." >&2; exit 1; }
for dependency in ip nft python3 curl timeout; do
  command -v "$dependency" >/dev/null || { echo "Missing: $dependency" >&2; exit 1; }
done
[[ -x bin/wirewall && -f bpf/wirewall_bpfel.o ]] || { echo "Build WireWall first." >&2; exit 1; }

client="ww-recovery-client-$$"
server="ww-recovery-server-$$"
client_link="wwrc-$$"
server_link="wwrs-$$"
client_created=0
server_created=0
veth_created=0
temporary=$(mktemp -d /tmp/wirewall-recovery-XXXXXX)
data="$temporary/state"
firewall_pid=
cleanup() {
  # Only an invocation that created this namespace may kill its members/delete it.
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
  case "$resolved" in /tmp/wirewall-recovery-*) rm -rf -- "$resolved" ;; esac
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
fail() {
  echo "$1" >&2
  [[ ! -f "$temporary/firewall.log" ]] || tail -n 30 "$temporary/firewall.log" >&2
  exit 1
}

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
  "rules":[{"id":"deny8081","name":"recovery test deny","enabled":true,"priority":10,
    "action":"drop","protocol":"tcp","source":"any","destination":"any",
    "sourcePort":"any","destinationPort":"8081","minPacketBytes":0,"maxPacketBytes":0,"pps":0,"burst":0}]
}
JSON

ip netns exec "$server" python3 -m http.server 8080 --bind 192.0.2.1 >"$temporary/service.log" 2>&1 &
ip netns exec "$server" python3 -m http.server 8081 --bind 192.0.2.1 >"$temporary/denied-service.log" 2>&1 &
baseline=0
for attempt in $(seq 1 30); do
  if ip netns exec "$client" curl --silent --fail --noproxy '*' --max-time 1 http://192.0.2.1:8080/ >/dev/null && \
     ip netns exec "$client" curl --silent --fail --noproxy '*' --max-time 1 http://192.0.2.1:8081/ >/dev/null; then
    baseline=1
    break
  fi
  sleep 0.2
done
[[ "$baseline" -eq 1 ]] || fail "Both baseline services must be reachable before recovery testing."
ip netns exec "$server" nft -j list tables >"$temporary/baseline-tables.json"
python3 - "$temporary/baseline-tables.json" <<'PY'
import json, sys
tables = [entry["table"] for entry in json.load(open(sys.argv[1]))["nftables"] if "table" in entry]
assert not tables, "Fresh test namespace unexpectedly contains nft tables"
PY

ip netns exec "$server" "$PWD/bin/wirewall" serve --backend xdp \
  --confirm-network-changes --object "$PWD/bpf/wirewall_bpfel.o" \
  --policy "$temporary/policy.json" --data "$data" --listen 127.0.0.1:9876 \
  >"$temporary/firewall.log" 2>&1 &
firewall_pid=$!

# The operator key stays inside Python memory; neither argv nor output contains it.
snapshot_ready() {
  ip netns exec "$server" python3 - "$data" "$1" <<'PY'
import datetime, json, pathlib, re, sys, urllib.request
token = None
try:
    token = (pathlib.Path(sys.argv[1]) / "operator.token").read_text().strip()
    request = urllib.request.Request("http://127.0.0.1:9876/api/v1/snapshot",
        headers={"Authorization": "Bearer " + token})
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open(request, timeout=2) as response:
        snapshot = json.load(response)
    system = snapshot["system"]
    assert system["backend"] == "xdp" and not system["simulated"], "Expected real XDP backend"
    assert system["attached"], "XDP attachment has not been observed"
    assert system["interface"] == "ww-server" and system["xdpMode"] == "generic", "Unexpected XDP interface/mode"
    assert system["activationPending"], "Activation must remain unconfirmed"
    errors = [item["name"] for item in system["health"] if item["status"] == "error"]
    assert not errors, "Unhealthy checks: " + ", ".join(errors)
    # Go RFC3339Nano may contain nine fractional digits; Python 3.10 accepts
    # microseconds. Normalize the fraction before parsing and retain UTC offset.
    value = re.sub(r"(\.\d{6})\d+", r"\1", system["activationDeadline"].replace("Z", "+00:00"))
    deadline = datetime.datetime.fromisoformat(value)
    assert (deadline - datetime.datetime.now(datetime.timezone.utc)).total_seconds() > 25, "Insufficient pending deadline remaining"
    if sys.argv[2] == "dropped":
        assert any(reason["reason"] == "rule_drop" and reason["count"] > 0
                   for reason in snapshot["metrics"]["reasons"]), "rule_drop counter has not advanced"
except Exception as error:
    message = type(error).__name__ + ": " + str(error)
    if token:
        message = message.replace(token, "[redacted]")
    print("Snapshot readiness: " + message, file=sys.stderr)
    raise SystemExit(1)
PY
}
ready=0
for attempt in $(seq 1 60); do
  kill -0 "$firewall_pid" 2>/dev/null || fail "Unconfirmed XDP process exited before readiness."
  if snapshot_ready ready 2>"$temporary/readiness.log"; then ready=1; break; fi
  sleep 0.5
done
if [[ "$ready" -ne 1 ]]; then
  tail -n 5 "$temporary/readiness.log" >&2
  fail "Authenticated snapshot did not prove attached/pending XDP."
fi
ip netns exec "$client" curl --silent --fail --noproxy '*' --max-time 2 http://192.0.2.1:8080/ >/dev/null
if ip netns exec "$client" curl --silent --noproxy '*' --max-time 1 http://192.0.2.1:8081/ >/dev/null; then
  fail "Denied service unexpectedly reachable before the crash."
fi
counted=0
for attempt in $(seq 1 10); do
  if snapshot_ready dropped 2>"$temporary/readiness.log"; then counted=1; break; fi
  sleep 0.5
done
if [[ "$counted" -ne 1 ]]; then
  tail -n 5 "$temporary/readiness.log" >&2
  fail "XDP rule_drop must advance before the crash."
fi
guard_path=$(python3 - "$data" <<'PY'
import pathlib, sys
records = list((pathlib.Path(sys.argv[1]) / "guards").glob("*.json"))
assert len(records) == 1, "Expected exactly one startup watchdog"
print(records[0])
PY
)
echo "Recovery test: attached/pending XDP and rule_drop proved; killing the main process."
kill -KILL "$firewall_pid"
wait "$firewall_pid" 2>/dev/null || true
firewall_pid=

# Different persistent state must not bypass the inherited namespace ownership.
set +e
ip netns exec "$server" timeout 5 "$PWD/bin/wirewall" serve --backend xdp \
  --confirm-network-changes --object "$PWD/bpf/wirewall_bpfel.o" \
  --policy "$temporary/policy.json" --data "$temporary/blocked-state" --listen 127.0.0.1:9877 \
  >"$temporary/restart.log" 2>&1
restart_status=$?
set -e
[[ "$restart_status" -ne 0 && "$restart_status" -ne 124 ]] || fail "Second startup was not promptly refused."
python3 - "$temporary/restart.log" "$temporary/blocked-state" <<'PY'
import pathlib, sys
assert "another WireWall daemon or rollback watchdog still owns this network namespace" in pathlib.Path(sys.argv[1]).read_text()
assert not pathlib.Path(sys.argv[2]).exists(), "Rejected restart created persistent state"
PY
ip netns exec "$server" nft list table inet wirewall >/dev/null
if ip netns exec "$client" curl --silent --noproxy '*' --max-time 1 http://192.0.2.1:8081/ >/dev/null; then
  fail "Host policy vanished before the independent watchdog deadline."
fi
echo "Recovery test: watchdog survived SIGKILL and refused a second state directory before database creation."

python3 - "$guard_path" <<'PY'
import datetime, json, pathlib, re, sys, time
record = pathlib.Path(sys.argv[1])
state = json.loads(record.read_text())
value = re.sub(r"(\.\d{6})\d+", r"\1", state["deadline"].replace("Z", "+00:00"))
deadline = datetime.datetime.fromisoformat(value)
remaining = (deadline - datetime.datetime.now(datetime.timezone.utc)).total_seconds()
assert 0 < remaining <= 90, "Unexpected watchdog deadline"
end = time.monotonic() + remaining + 35  # Recovery itself has a 30-second timeout.
last_report = time.monotonic()
print("Recovery test: waiting for the unconfirmed 90-second activation rollback.", flush=True)
while time.monotonic() < end:
    failure = pathlib.Path(str(record) + ".failed")
    if failure.exists():
        raise AssertionError("Watchdog reported failed recovery: " + failure.read_text().strip())
    completed = pathlib.Path(str(record) + ".rolledback")
    if completed.exists():
        assert completed.read_text().strip() == "rollback completed"
        assert pathlib.Path(str(record) + ".outcome").read_text().strip() == "rollback"
        break
    if time.monotonic() - last_report >= 15:
        print("Recovery test: independent watchdog is still pending.", flush=True)
        last_report = time.monotonic()
    time.sleep(0.2)
else:
    raise AssertionError("Independent watchdog did not complete within deadline plus recovery timeout")
PY

ip netns exec "$server" nft -j list tables >"$temporary/recovered-tables.json"
ip -n "$server" -j link show dev ww-server >"$temporary/recovered-link.json"
python3 - "$temporary" "$guard_path" <<'PY'
import json, pathlib, sqlite3, sys
root, record = pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2])
tables = [entry["table"] for entry in json.loads((root / "recovered-tables.json").read_text())["nftables"] if "table" in entry]
assert not tables, "Watchdog did not restore the empty baseline nft ruleset"
link = json.loads((root / "recovered-link.json").read_text())[0]
xdp = link.get("xdp", {})
assert not xdp.get("prog", {}).get("id") and not xdp.get("attached"), "XDP remained attached after the parent crash/recovery"
state = json.loads(record.read_text())
with sqlite3.connect(str(root / "state/wirewall.db")) as connection:
    policy, bans = connection.execute("SELECT policy,bans FROM state WHERE id=1").fetchone()
    assert json.loads(policy) == state["previousPolicy"], "Persisted policy was not restored"
    assert json.loads(bans) == state["previousBans"], "Persisted bans were not restored"
    assert connection.execute("SELECT count(*) FROM audit WHERE action='activation.rollback'").fetchone()[0] == 1
assert not pathlib.Path(str(record) + ".failed").exists()
PY
ip netns exec "$client" curl --silent --fail --noproxy '*' --max-time 2 http://192.0.2.1:8080/ >/dev/null
ip netns exec "$client" curl --silent --fail --noproxy '*' --max-time 2 http://192.0.2.1:8081/ >/dev/null

# A missing bootstrap fails after lease acquisition/store opening but before any
# runtime/network mutation. Its DB proves the previous namespace lease released.
released=0
for attempt in $(seq 1 20); do
  set +e
  ip netns exec "$server" timeout 5 "$PWD/bin/wirewall" serve --backend xdp \
    --confirm-network-changes --policy "$temporary/missing-policy.json" \
    --data "$temporary/released-state" --listen 127.0.0.1:9877 \
    >"$temporary/released.log" 2>&1
  release_status=$?
  set -e
  if [[ "$release_status" -ne 0 && "$release_status" -ne 124 ]] && \
     [[ -f "$temporary/released-state/wirewall.db" ]]; then released=1; break; fi
  sleep 0.1
done
[[ "$released" -eq 1 ]] || fail "Namespace ownership did not release after completed recovery."
python3 - "$temporary/released.log" <<'PY'
import pathlib, sys
message = pathlib.Path(sys.argv[1]).read_text()
assert "missing-policy.json" in message and "no such file" in message
assert "still owns this network namespace" not in message
PY
echo "Recovery test passed: independent rollback restored nft/SQLite, XDP is detached, both services work, ownership is released."
echo "Only disposable namespaces/veths were used; no host uplink or host firewall table was modified."
