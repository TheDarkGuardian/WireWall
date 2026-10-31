#!/usr/bin/env bash
# Explicitly authorized isolated Linux benchmark. Never uses a real host uplink.
set -euo pipefail
export PYTHONDONTWRITEBYTECODE=1
cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.."
[[ ${EUID} -eq 0 ]] || { echo "Run inside the Ubuntu lab as root." >&2; exit 1; }
[[ ${WIREWALL_ALLOW_NETNS_BENCHMARK:-} == 1 ]] || { echo "Explicit WIREWALL_ALLOW_NETNS_BENCHMARK=1 opt-in required." >&2; exit 1; }

duration=5
warmup=1
legitimate_rate=500
background_rate=5000
repetitions=5
include_native=0
payload_bytes=64
rule_count=1
output="$PWD/.local/benchmark-$(date -u +%Y%m%dT%H%M%SZ)-$$"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --duration) duration=${2:?duration required}; shift 2 ;;
    --warmup) warmup=${2:?warmup required}; shift 2 ;;
    --legitimate-rate) legitimate_rate=${2:?rate required}; shift 2 ;;
    --background-rate) background_rate=${2:?rate required}; shift 2 ;;
    --repetitions) repetitions=${2:?count required}; shift 2 ;;
    --output) output=${2:?directory required}; shift 2 ;;
    --include-native) include_native=1; shift ;;
    --payload-bytes) payload_bytes=${2:?bytes required}; shift 2 ;;
    --rule-count) rule_count=${2:?count required}; shift 2 ;;
    *) echo "Unknown option: $1" >&2; exit 1 ;;
  esac
done
[[ "$payload_bytes" =~ ^[0-9]+$ && "$payload_bytes" -ge 32 && "$payload_bytes" -le 1400 ]] || { echo 'Payload must be 32..1400'; exit 1; }
[[ "$rule_count" =~ ^[0-9]+$ && "$rule_count" -ge 1 && "$rule_count" -le 64 ]] || { echo 'Rules must be 1..64'; exit 1; }
export WIREWALL_BENCH_PAYLOAD_BYTES="$payload_bytes"
export WIREWALL_BENCH_RULE_COUNT="$rule_count"
for dependency in ip python3 nft realpath; do
  command -v "$dependency" >/dev/null || { echo "Missing dependency: $dependency" >&2; exit 1; }
done
[[ -x bin/wirewall && -f bpf/wirewall_bpfel.o ]] || { echo "Build the Linux binary and BPF object first." >&2; exit 1; }
python3 - "$duration" "$warmup" "$legitimate_rate" "$background_rate" "$repetitions" <<'PY'
import importlib.util, math, sys
spec = importlib.util.spec_from_file_location("ww_bench", "scripts/linux/bench_traffic.py")
module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
duration, warmup = map(float, sys.argv[1:3])
legitimate, background, repeats = map(int, sys.argv[3:])
module.validate_rates(duration, legitimate, background)
module.validate_rates(warmup, legitimate, background)
if not 0.1 <= warmup <= 5 or not 5 <= repeats <= 20:
    raise SystemExit("Warmup must be 0.1..5 seconds; repetitions 5..20.")
PY

# A new output directory is mandatory. Never overwrite a previous experiment.
mkdir -p -- "$(dirname -- "$output")"
mkdir -m 0700 -- "$output"
output=$(realpath -- "$output")
temporary=$(mktemp -d /tmp/wirewall-benchmark-XXXXXX)
chmod 0700 "$temporary"
client_namespace=
server_namespace=
client_created=0
server_created=0
veth_created=0
client_link=
firewall_pid=
echo_pid=

cleanup_run() {
  # All processes in these freshly created namespaces belong to this run,
  # including an unconfirmed activation watchdog after an early startup error.
  for namespace in "$server_namespace" "$client_namespace"; do
    [[ -n "$namespace" ]] || continue
    if [[ "$namespace" == "$server_namespace" && "$server_created" -eq 1 ]] || \
       [[ "$namespace" == "$client_namespace" && "$client_created" -eq 1 ]]; then
      while read -r process; do [[ -z "$process" ]] || kill "$process" 2>/dev/null || true; done < <(ip netns pids "$namespace" 2>/dev/null)
    fi
  done
  for attempt in $(seq 1 20); do
    remaining=
    [[ "$server_created" -eq 0 ]] || remaining=$(ip netns pids "$server_namespace" 2>/dev/null || true)
    [[ -z "$remaining" ]] && break
    sleep 0.1
  done
  if [[ "$server_created" -eq 1 ]]; then
    while read -r process; do [[ -z "$process" ]] || kill -KILL "$process" 2>/dev/null || true; done < <(ip netns pids "$server_namespace" 2>/dev/null)
    ip netns del "$server_namespace" 2>/dev/null || true
  fi
  [[ "$client_created" -eq 0 ]] || ip netns del "$client_namespace" 2>/dev/null || true
  if [[ "$veth_created" -eq 1 && -n "$client_link" ]] && ip link show dev "$client_link" >/dev/null 2>&1; then
    ip link del dev "$client_link" 2>/dev/null || true
  fi
  [[ -z "$firewall_pid" ]] || wait "$firewall_pid" 2>/dev/null || true
  [[ -z "$echo_pid" ]] || wait "$echo_pid" 2>/dev/null || true
  client_created=0; server_created=0; veth_created=0; firewall_pid=; echo_pid=
}
cleanup() {
  cleanup_run
  resolved=$(realpath -- "$temporary")
  case "$resolved" in /tmp/wirewall-benchmark-*) rm -rf -- "$resolved" ;; esac
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

uname -a >"$output/kernel.txt"
if command -v lscpu >/dev/null; then lscpu -J >"$output/cpu.json"; fi
"$PWD/bin/wirewall" version >"$output/wirewall-version.txt"
python3 - "$output/configuration.json" "$duration" "$warmup" "$legitimate_rate" "$background_rate" "$repetitions" "$include_native" <<'PY'
import json, platform, sys
path, duration, warmup, legitimate, background, repeats, native = sys.argv[1:]
value = {"durationSeconds":float(duration),"warmupSeconds":float(warmup),
 "requestedLegitimatePPS":int(legitimate),"requestedBackgroundPPS":int(background),
 "repetitions":int(repeats),"includeNative":bool(int(native)),"python":platform.python_version(),
 "topology":"fresh client/server netns and veth for every run; no default routes",
 "payloadBytes":int(__import__('os').environ['WIREWALL_BENCH_PAYLOAD_BYTES']),"ruleCount":int(__import__('os').environ['WIREWALL_BENCH_RULE_COUNT']),"ports":{"legitimate":9000,"background":9001},
 "externalPacketCapture":False,"builtInXDPEventSampling":"1/64, bounded to 64 events/s; cost included",
 "cpuScope":"echo-server process and separately labelled shared host aggregate; neither is exclusive firewall CPU",
 "limitations":["client/server share this host","Python traffic generator may bottleneck",
 "no physical NIC benchmark","no upstream mitigation capacity result"]}
with open(path,"w",encoding="utf-8") as stream: json.dump(value,stream,indent=2)
PY

modes=(baseline nft generic)
[[ "$include_native" -eq 0 ]] || modes+=(native)
run_number=0
for ((repetition=1; repetition<=repetitions; repetition++)); do
  # Rotate order across repetitions to reduce a fixed warm/cold order bias.
  for ((position=0; position<${#modes[@]}; position++)); do
    mode=${modes[$(((position + repetition - 1) % ${#modes[@]}))]}
    run_number=$((run_number + 1))
    run_output="$output/run-$(printf '%03d' "$run_number")-$mode-$repetition"
    mkdir -m 0700 -- "$run_output"
    run_temporary="$temporary/run-$run_number"
    mkdir -m 0700 -- "$run_temporary"
    client_namespace="wwb-c-$$-$run_number"; server_namespace="wwb-s-$$-$run_number"
    # Kernel interface names are capped at 15 bytes; namespace names are not.
    client_link="bc$$"; server_link="bs$$"
    ip netns add "$client_namespace"; client_created=1
    ip netns add "$server_namespace"; server_created=1
    ip link add "$client_link" type veth peer name "$server_link"; veth_created=1
    ip link set "$client_link" netns "$client_namespace"
    # The pair is now owned through a namespace. Deleting that namespace
    # removes both ends, even if moving the second end subsequently fails.
    # Do not later remove an unrelated host interface that reuses this name.
    veth_created=0
    ip link set "$server_link" netns "$server_namespace"
    ip -n "$client_namespace" link set "$client_link" name ww-client
    ip -n "$server_namespace" link set "$server_link" name ww-server
    ip -n "$client_namespace" link set lo up
    ip -n "$server_namespace" link set lo up
    ip -n "$client_namespace" address add 10.203.0.1/24 dev ww-client
    ip -n "$server_namespace" address add 10.203.0.2/24 dev ww-server
    ip -n "$client_namespace" link set ww-client mtu 1500 up
    ip -n "$server_namespace" link set ww-server mtu 1500 up
    ip -n "$server_namespace" -j -details link show ww-server >"$run_output/interface-before.json"
    ip -n "$client_namespace" route show >"$run_output/client-routes.txt"
    ip -n "$server_namespace" route show >"$run_output/server-routes.txt"
    if command -v ethtool >/dev/null; then
      ip netns exec "$server_namespace" ethtool -k ww-server >"$run_output/offloads.txt" 2>&1 || true
      ip netns exec "$server_namespace" ethtool -i ww-server >"$run_output/driver.txt" 2>&1 || true
    fi
    python3 - "$run_output/policy.json" "$run_output/run.json" "$mode" "$repetition" <<'PY'
import json,sys,os,copy
policy_path,meta_path,mode,repetition=sys.argv[1:]
policy={"version":1,"mode":"enforce","interface":"ww-server",
 "xdpMode":"native" if mode=="native" else "generic","managementCidrs":["10.203.0.1/32"],"managementPort":22,
 "host":{"tcpPorts":[],"udpPorts":[9000],"ipv6":False},
 "rules":[{"id":"background-drop","name":"Controlled benchmark background","enabled":True,"priority":10,
 "action":"drop","protocol":"udp","source":"any","destination":"any","sourcePort":"any",
 "destinationPort":"9001","minPacketBytes":0,"maxPacketBytes":0,"pps":0,"burst":0}]}
count=int(os.environ['WIREWALL_BENCH_RULE_COUNT'])
padding=[]
for i in range(count-1):
 rule=copy.deepcopy(policy['rules'][0]);rule.update(id='padding-'+str(i),name='Nonmatching source '+str(i),priority=i,source='10.203.0.254/32');padding.append(rule)
policy['rules'][0]['priority']=100
policy['rules']=padding+policy['rules']
with open(policy_path,"w",encoding="utf-8") as stream:json.dump(policy,stream,indent=2)
with open(meta_path,"w",encoding="utf-8") as stream:json.dump({"mode":mode,"repetition":int(repetition)},stream)
PY
    "$PWD/bin/wirewall" validate --policy "$run_output/policy.json" >"$run_output/policy-validation.txt"
    ip netns exec "$server_namespace" python3 "$PWD/scripts/linux/bench_traffic.py" server --ready "$run_temporary/echo-ready.json" >"$run_output/echo.log" 2>&1 &
    echo_pid=$!
    for attempt in $(seq 1 40); do
      [[ ! -f "$run_temporary/echo-ready.json" ]] || break
      kill -0 "$echo_pid" 2>/dev/null || { echo "Echo server failed; see $run_output/echo.log" >&2; exit 1; }
      sleep 0.1
    done
    [[ -f "$run_temporary/echo-ready.json" ]] || { echo "Echo server readiness timeout" >&2; exit 1; }

    if [[ "$mode" == nft ]]; then
      "$PWD/bin/wirewall" render-nft --policy "$run_output/policy.json" >"$run_output/rules.nft"
      ip netns exec "$server_namespace" nft --check --file "$run_output/rules.nft"
      ip netns exec "$server_namespace" nft --file "$run_output/rules.nft"
    elif [[ "$mode" == generic || "$mode" == native ]]; then
      ip netns exec "$server_namespace" "$PWD/bin/wirewall" serve --backend xdp --confirm-network-changes \
        --policy "$run_output/policy.json" --object "$PWD/bpf/wirewall_bpfel.o" \
        --data "$run_temporary/data" --listen 127.0.0.1:9876 >"$run_output/firewall.log" 2>&1 &
      firewall_pid=$!
      ready=0
      for attempt in $(seq 1 60); do
        kill -0 "$firewall_pid" 2>/dev/null || { echo "XDP $mode startup failed; see $run_output/firewall.log. No fallback used." >&2; exit 1; }
        if ip netns exec "$server_namespace" python3 "$PWD/scripts/linux/bench_traffic.py" api --path health --output "$run_temporary/health.json" 2>/dev/null; then ready=1; break; fi
        sleep 0.25
      done
      [[ "$ready" -eq 1 ]] || { echo "XDP readiness timed out" >&2; exit 1; }
      # This confirmation is appropriate only in these disposable namespaces.
      ip netns exec "$server_namespace" python3 "$PWD/scripts/linux/bench_traffic.py" api --path policy/confirm \
        --token-file "$run_temporary/data/operator.token" --output "$run_temporary/confirmed.json"
    fi

    ip -n "$server_namespace" -j -details link show ww-server >"$run_output/interface-active.json"
    ip netns exec "$client_namespace" python3 "$PWD/scripts/linux/bench_traffic.py" client --duration "$warmup" \
      --legitimate-rate "$legitimate_rate" --background-rate "$background_rate" --output "$run_output/warmup.json"
    sleep 1.1
    if [[ -n "$firewall_pid" ]]; then
      ip netns exec "$server_namespace" python3 "$PWD/scripts/linux/bench_traffic.py" api --path snapshot \
        --token-file "$run_temporary/data/operator.token" --output "$run_output/xdp-before.json"
    elif [[ "$mode" == nft ]]; then
      ip netns exec "$server_namespace" nft -j list table inet wirewall >"$run_output/nft-before.json"
    fi
    python3 "$PWD/scripts/linux/bench_traffic.py" process-cpu --pid "$echo_pid" --output "$run_output/server-cpu-before.json"
    python3 "$PWD/scripts/linux/bench_traffic.py" host-cpu --output "$run_output/host-cpu-before.json"
    ip netns exec "$client_namespace" python3 "$PWD/scripts/linux/bench_traffic.py" client --duration "$duration" \
      --legitimate-rate "$legitimate_rate" --background-rate "$background_rate" --output "$run_output/client.json"
    python3 "$PWD/scripts/linux/bench_traffic.py" process-cpu --pid "$echo_pid" --output "$run_output/server-cpu-after.json"
    python3 "$PWD/scripts/linux/bench_traffic.py" host-cpu --output "$run_output/host-cpu-after.json"
    sleep 1.1
    if [[ -n "$firewall_pid" ]]; then
      ip netns exec "$server_namespace" python3 "$PWD/scripts/linux/bench_traffic.py" api --path snapshot \
        --token-file "$run_temporary/data/operator.token" --output "$run_output/xdp-after.json"
    elif [[ "$mode" == nft ]]; then
      ip netns exec "$server_namespace" nft -j list table inet wirewall >"$run_output/nft-after.json"
    fi
    python3 - "$run_output/client.json" "$mode" <<'PY'
import json,sys
with open(sys.argv[1],encoding="utf-8") as stream:data=json.load(stream)
legit=data["streams"]["legitimate"]
if not legit["sentPackets"] or not legit["receivedUniquePackets"]:
    raise SystemExit("No legitimate service echo observed; run is not a usable comparison.")
background=data["streams"].get("background")
if background:
    if not background["sentPackets"]:
        raise SystemExit("Requested background has no successfully sent packets.")
    if sys.argv[2]=="baseline" and not background["receivedUniquePackets"]:
        raise SystemExit("Baseline background echo is not reachable.")
    if sys.argv[2]!="baseline" and background["receivedUniquePackets"]:
        raise SystemExit("Blocked background unexpectedly reached the echo service.")
PY
    if [[ "$mode" == generic || "$mode" == native ]]; then
      python3 - "$run_output" "$mode" <<'PY'
import json,sys
from pathlib import Path
root=Path(sys.argv[1])
before=json.loads((root/"xdp-before.json").read_text(encoding="utf-8"))
after=json.loads((root/"xdp-after.json").read_text(encoding="utf-8"))
client=json.loads((root/"client.json").read_text(encoding="utf-8"))
if not after["system"]["attached"] or after["system"]["xdpMode"]!=sys.argv[2]:
    raise SystemExit("Reported XDP attachment/mode does not match this experiment.")
def counter(value):
    return next((item["count"] for item in value["metrics"]["reasons"] if item["reason"]=="rule_drop"),0)
if client["streams"].get("background",{}).get("sentPackets",0)>0 and counter(after)<=counter(before):
    raise SystemExit("Background was blocked without an advancing unsampled XDP rule_drop counter.")
PY
    fi
    printf 'Completed %s repetition %s\n' "$mode" "$repetition"
    cleanup_run
  done
done
python3 "$PWD/scripts/linux/bench_traffic.py" summarize --root "$output"
printf 'Raw benchmark artifacts and summary: %s\n' "$output"
echo "Results describe isolated namespace/veth behavior, not physical NIC or upstream capacity."
