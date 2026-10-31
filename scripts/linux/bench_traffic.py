#!/usr/bin/env python3
"""Bounded traffic and result helpers for WireWall's isolated namespace bench.

Traffic commands require an explicit opt-in and a network namespace different
from PID 1. No arbitrary target, port, or external network is supported.
Importing this module or running its offline tests never opens a socket.
"""
from __future__ import annotations

import argparse
import csv
import ipaddress
import json
import math
import os
from pathlib import Path
import platform
import secrets
import selectors
import signal
import socket
import statistics
import struct
import time
import urllib.error
import urllib.request

try:
    import resource
except ImportError:  # Offline parser/statistics tests also run on Windows.
    resource = None

CLIENT = "10.203.0.1"
SERVER = "10.203.0.2"
PORTS = {"legitimate": 9000, "background": 9001}
HEADER = struct.Struct("!8sBIQ")
PAYLOAD_BYTES = int(os.environ.get("WIREWALL_BENCH_PAYLOAD_BYTES", "64"))
if not 32 <= PAYLOAD_BYTES <= 1400:
    raise ValueError("benchmark payload must be 32..1400 bytes (no fragmentation)")
MAX_RATE = 50_000
MAX_LEGITIMATE_RATE = 5_000
MAX_DURATION = 30.0
MAX_DATAGRAMS = 1_500_064


def write_json(path: str | Path, value: object) -> None:
    output = Path(path)
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = output.with_name(output.name + ".writing")
    temporary.write_text(json.dumps(value, indent=2, allow_nan=False) + "\n", encoding="utf-8")
    os.chmod(temporary, 0o600)
    temporary.replace(output)


def validate_rates(duration: float, legitimate_rate: int, background_rate: int) -> None:
    if not math.isfinite(duration) or not 0.1 <= duration <= MAX_DURATION:
        raise ValueError("duration must be finite and between 0.1 and 30 seconds")
    if not 1 <= legitimate_rate <= MAX_LEGITIMATE_RATE:
        raise ValueError("legitimate rate must be 1..5000 packets/second")
    if not 0 <= background_rate <= MAX_RATE or legitimate_rate + background_rate > MAX_RATE:
        raise ValueError("combined offered rate must not exceed 50000 packets/second")
    if math.ceil((legitimate_rate + background_rate) * duration) + 64 > MAX_DATAGRAMS:
        raise ValueError("datagram budget exceeded")


def validate_target(target: str) -> str:
    try:
        address = ipaddress.ip_address(target)
    except ValueError as error:
        raise ValueError("only the fixed literal namespace server address is supported") from error
    if str(address) != SERVER:
        raise ValueError("target must be the fixed isolated namespace address 10.203.0.2")
    return str(address)


def require_isolated_namespace() -> None:
    if platform.system() != "Linux":
        raise RuntimeError("traffic commands run only in the later Linux laboratory")
    if os.environ.get("WIREWALL_ALLOW_NETNS_BENCHMARK") != "1":
        raise RuntimeError("set WIREWALL_ALLOW_NETNS_BENCHMARK=1 explicitly")
    if os.geteuid() != 0:
        raise RuntimeError("the namespace harness requires root")
    if os.readlink("/proc/self/ns/net") == os.readlink("/proc/1/ns/net"):
        raise RuntimeError("refusing traffic in PID 1's network namespace")


def percentile(values: list[float], fraction: float) -> float | None:
    """Nearest-rank percentile; no invented latency when no echo arrives."""
    if not values:
        return None
    if not 0 < fraction <= 1 or not all(math.isfinite(item) and item >= 0 for item in values):
        raise ValueError("invalid percentile input")
    ordered = sorted(values)
    return ordered[max(0, math.ceil(len(ordered) * fraction) - 1)]


def due_packets(now: float, next_send: float, rate: int) -> int:
    # int(negative_fraction) truncates toward zero, so a generic int(...)+1
    # expression could send early whenever an echo wakes the selector.
    if now < next_send:
        return 0
    return min(64, math.floor((now - next_send) * rate) + 1)


def parse_proc_cpu(text: str, ticks_per_second: int) -> dict[str, float]:
    # comm is parenthesized and can contain spaces or ')'. Fields after its last
    # closing parenthesis start at field 3; utime/stime are fields 14 and 15.
    close = text.rfind(")")
    fields = text[close + 1:].split() if close >= 0 else []
    if len(fields) < 13 or ticks_per_second <= 0:
        raise ValueError("invalid /proc/PID/stat record")
    user, system = int(fields[11]), int(fields[12])
    if min(user, system) < 0:
        raise ValueError("negative process CPU counter")
    return {"userSeconds": user / ticks_per_second, "systemSeconds": system / ticks_per_second}


def process_cpu(pid: int) -> dict[str, float]:
    if pid < 1:
        raise ValueError("positive process ID required")
    return parse_proc_cpu(Path(f"/proc/{pid}/stat").read_text(encoding="utf-8"), os.sysconf("SC_CLK_TCK"))


def parse_host_cpu(text: str, ticks_per_second: int) -> dict:
    fields = text.splitlines()[0].split() if text else []
    if len(fields) < 5 or fields[0] != "cpu" or ticks_per_second < 1:
        raise ValueError("invalid aggregate host CPU record")
    names = ("user", "nice", "system", "idle", "iowait", "irq", "softirq", "steal")
    values = [int(value) for value in fields[1:9]]
    if any(value < 0 for value in values):
        raise ValueError("negative aggregate CPU counter")
    values += [0] * (len(names) - len(values))
    return {"ticksPerSecond": ticks_per_second, "ticks": dict(zip(names, values)),
            "scope": "shared host/VM aggregate including client, echo, firewall and other workloads"}


def host_cpu_delta(before: dict, after: dict) -> dict:
    if before["ticksPerSecond"] != after["ticksPerSecond"]:
        raise ValueError("aggregate CPU clock changed")
    delta = {name: after["ticks"][name] - value for name, value in before["ticks"].items()}
    if any(value < 0 for value in delta.values()):
        raise ValueError("aggregate CPU counters reset during the run")
    total = sum(delta.values())
    busy = total - delta["idle"] - delta["iowait"]
    ticks = before["ticksPerSecond"]
    return {"busyPercent": busy * 100 / total if total else None,
            "softirqSeconds": delta["softirq"] / ticks, "stealSeconds": delta["steal"] / ticks}


def run_server(ready: str) -> None:
    require_isolated_namespace()
    stop = False

    def stopping(_signal: int, _frame: object) -> None:
        nonlocal stop
        stop = True

    signal.signal(signal.SIGTERM, stopping)
    signal.signal(signal.SIGINT, stopping)
    with selectors.DefaultSelector() as selector:
        sockets: list[socket.socket] = []
        try:
            for port in PORTS.values():
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.bind((SERVER, port))
                sock.setblocking(False)
                selector.register(sock, selectors.EVENT_READ)
                sockets.append(sock)
            write_json(ready, {"ready": True, "host": SERVER, "ports": list(PORTS.values()), "pid": os.getpid()})
            while not stop:
                for key, _ in selector.select(timeout=0.2):
                    sock = key.fileobj
                    for _ in range(256):
                        try:
                            payload, peer = sock.recvfrom(2048)
                        except BlockingIOError:
                            break
                        # Replies never leave this fixed client/server pair.
                        if peer[0] == CLIENT and len(payload) == PAYLOAD_BYTES:
                            try:
                                sock.sendto(payload, peer)
                            except (BlockingIOError, ConnectionRefusedError):
                                pass
        finally:
            for sock in sockets:
                sock.close()


def run_client(duration: float, legitimate_rate: int, background_rate: int, target: str) -> dict:
    validate_rates(duration, legitimate_rate, background_rate)
    target = validate_target(target)
    require_isolated_namespace()
    if resource is None:
        raise RuntimeError("Linux resource accounting is unavailable")
    nonce = secrets.token_bytes(8)
    streams = []
    latency_ms: list[float] = []
    before_cpu = resource.getrusage(resource.RUSAGE_SELF)
    start = time.monotonic()
    start_ns = time.monotonic_ns()
    deadline = start + duration
    send_elapsed = duration
    with selectors.DefaultSelector() as selector:
        try:
            for index, (name, rate) in enumerate((("legitimate", legitimate_rate), ("background", background_rate))):
                if not rate:
                    continue
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.bind((CLIENT, 0))
                sock.setblocking(False)
                stream = {"name": name, "rate": rate, "sock": sock, "index": index,
                          "next": start, "sent": 0, "received": 0, "duplicates": 0,
                          "sendErrors": 0, "invalidReplies": 0, "schedulerResets": 0,
                          "seen": bytearray(math.ceil(rate * duration) + 65)}
                selector.register(sock, selectors.EVENT_READ, stream)
                streams.append(stream)
            sending = True
            drain_deadline = deadline + 0.3
            while True:
                now = time.monotonic()
                if sending and now >= deadline:
                    sending = False
                    send_elapsed = now - start
                    drain_deadline = now + 0.3
                if not sending and now >= drain_deadline:
                    break
                if sending:
                    for stream in streams:
                        interval = 1 / stream["rate"]
                        # Catch up only a bounded batch. A delayed scheduler is
                        # recorded, never converted into an unbounded burst.
                        due = due_packets(now, stream["next"], stream["rate"])
                        for _ in range(due):
                            sequence = stream["sent"]
                            if sequence >= len(stream["seen"]):
                                raise RuntimeError("bounded sequence budget exceeded")
                            stamp = time.monotonic_ns()
                            payload = HEADER.pack(nonce, stream["index"], sequence, stamp)
                            payload += b"w" * (PAYLOAD_BYTES - len(payload))
                            try:
                                stream["sock"].sendto(payload, (target, PORTS[stream["name"]]))
                                stream["sent"] += 1
                            except (BlockingIOError, OSError):
                                stream["sendErrors"] += 1
                            stream["next"] += interval
                        if now - stream["next"] > 0.1:
                            stream["schedulerResets"] += 1
                            stream["next"] = now + interval
                next_due = min((stream["next"] for stream in streams), default=now + 0.01)
                timeout = min(0.01, max(0, next_due - time.monotonic())) if sending else 0.01
                for key, _ in selector.select(timeout=timeout):
                    stream = key.data
                    for _ in range(512):
                        try:
                            payload, peer = stream["sock"].recvfrom(2048)
                        except (BlockingIOError, ConnectionRefusedError):
                            break
                        if peer != (target, PORTS[stream["name"]]) or len(payload) != PAYLOAD_BYTES:
                            stream["invalidReplies"] += 1
                            continue
                        got_nonce, kind, sequence, stamp = HEADER.unpack_from(payload)
                        received_ns = time.monotonic_ns()
                        if got_nonce != nonce or kind != stream["index"] or sequence >= stream["sent"] or not start_ns <= stamp <= received_ns:
                            stream["invalidReplies"] += 1
                            continue
                        if stream["seen"][sequence]:
                            stream["duplicates"] += 1
                            continue
                        stream["seen"][sequence] = 1
                        stream["received"] += 1
                        if stream["name"] == "legitimate":
                            latency_ms.append((received_ns - stamp) / 1_000_000)
        finally:
            for stream in streams:
                stream["sock"].close()
    after_cpu = resource.getrusage(resource.RUSAGE_SELF)
    result = {"target": target, "payloadBytes": PAYLOAD_BYTES, "requestedDurationSeconds": duration,
              "sendElapsedSeconds": send_elapsed, "replyDrainSeconds": 0.3,
              "clientProcessCPU": {"userSeconds": after_cpu.ru_utime - before_cpu.ru_utime,
                                   "systemSeconds": after_cpu.ru_stime - before_cpu.ru_stime},
              "streams": {}}
    for stream in streams:
        sent, received = stream["sent"], stream["received"]
        result["streams"][stream["name"]] = {
            "requestedPPS": stream["rate"], "sentPackets": sent, "receivedUniquePackets": received,
            "offeredPPS": sent / send_elapsed, "receivedPPS": received / send_elapsed,
            "successRatio": received / sent if sent else None,
            "sentApplicationBytes": sent * PAYLOAD_BYTES,
            "duplicates": stream["duplicates"], "sendErrors": stream["sendErrors"],
            "invalidReplies": stream["invalidReplies"], "schedulerResets": stream["schedulerResets"],
        }
    result["legitimateRTT"] = {"samples": len(latency_ms), "p50Milliseconds": percentile(latency_ms, 0.5),
                               "p95Milliseconds": percentile(latency_ms, 0.95)}
    return result


def api_call(token_file: str, path: str, output: str) -> None:
    require_isolated_namespace()
    if path not in ("health", "snapshot", "policy/confirm"):
        raise ValueError("unsupported benchmark API operation")
    headers = {}
    if path != "health":
        token = Path(token_file).read_text(encoding="utf-8").strip()
        if len(token) < 32:
            raise ValueError("invalid operator token file")
        headers["Authorization"] = "Bearer " + token
    body = b"{}" if path == "policy/confirm" else None
    if body is not None:
        headers["Content-Type"] = "application/json"
    request = urllib.request.Request("http://127.0.0.1:9876/api/v1/" + path, data=body, headers=headers)
    # Ignore proxy environment variables for the namespace loopback API.
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open(request, timeout=3) as response:
        value = json.load(response)
    write_json(output, value)


def summarize(root: Path) -> None:
    rows = []
    for path in sorted(root.glob("run-*/client.json")):
        data = json.loads(path.read_text(encoding="utf-8"))
        metadata = json.loads((path.parent / "run.json").read_text(encoding="utf-8"))
        legitimate = data["streams"]["legitimate"]
        background = data["streams"].get("background", {})
        before = json.loads((path.parent / "server-cpu-before.json").read_text(encoding="utf-8"))
        after = json.loads((path.parent / "server-cpu-after.json").read_text(encoding="utf-8"))
        cpu = {key: after[key] - before[key] for key in ("userSeconds", "systemSeconds")}
        if any(value < 0 for value in cpu.values()):
            raise ValueError("server process counters reset during a run")
        aggregate = {"busyPercent":None,"softirqSeconds":None,"stealSeconds":None}
        if (path.parent/"host-cpu-before.json").exists() and (path.parent/"host-cpu-after.json").exists():
            aggregate=host_cpu_delta(json.loads((path.parent/"host-cpu-before.json").read_text(encoding="utf-8")),
                                     json.loads((path.parent/"host-cpu-after.json").read_text(encoding="utf-8")))
        rows.append({"mode": metadata["mode"], "repetition": metadata["repetition"],
                     "offeredLegitimatePPS": legitimate["offeredPPS"],
                     "offeredBackgroundPPS": background.get("offeredPPS", 0),
                     "legitimateSuccessRatio": legitimate["successRatio"],
                     "backgroundSuccessRatio": background.get("successRatio"),
                     "legitimateP95Milliseconds": data["legitimateRTT"]["p95Milliseconds"],
                     "echoServerUserCPUSeconds": cpu["userSeconds"],
                     "echoServerSystemCPUSeconds": cpu["systemSeconds"],
                     "clientUserCPUSeconds": data["clientProcessCPU"]["userSeconds"],
                     "clientSystemCPUSeconds": data["clientProcessCPU"]["systemSeconds"],
                     "sharedHostBusyPercent":aggregate["busyPercent"],
                     "sharedHostSoftirqSeconds":aggregate["softirqSeconds"],
                     "sharedHostStealSeconds":aggregate["stealSeconds"],
                     "rawResult": str(path.relative_to(root))})
    if not rows:
        raise ValueError("no completed benchmark results")
    with (root / "summary.csv").open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    groups = []
    for mode in sorted({row["mode"] for row in rows}):
        selected = [row for row in rows if row["mode"] == mode]
        group = {"mode": mode, "repetitions": len(selected)}
        for key in ("offeredLegitimatePPS", "offeredBackgroundPPS", "legitimateSuccessRatio",
                    "backgroundSuccessRatio", "legitimateP95Milliseconds", "echoServerUserCPUSeconds",
                    "echoServerSystemCPUSeconds", "clientUserCPUSeconds", "clientSystemCPUSeconds",
                    "sharedHostBusyPercent", "sharedHostSoftirqSeconds", "sharedHostStealSeconds"):
            values = [row[key] for row in selected if row[key] is not None]
            group[key] = {"median": statistics.median(values), "minimum": min(values), "maximum": max(values)} if values else None
        groups.append(group)
    write_json(root / "summary.json", {"groups": groups, "runs": rows,
        "scope": "isolated veth/namespace measurements; no physical NIC or upstream mitigation result"})


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    commands = result.add_subparsers(dest="command", required=True)
    server = commands.add_parser("server")
    server.add_argument("--ready", required=True)
    client = commands.add_parser("client")
    client.add_argument("--target", default=SERVER)
    client.add_argument("--duration", type=float, default=5)
    client.add_argument("--legitimate-rate", type=int, default=500)
    client.add_argument("--background-rate", type=int, default=5000)
    client.add_argument("--output", required=True)
    cpu = commands.add_parser("process-cpu")
    cpu.add_argument("--pid", type=int, required=True)
    cpu.add_argument("--output", required=True)
    aggregate = commands.add_parser("host-cpu")
    aggregate.add_argument("--output", required=True)
    api = commands.add_parser("api")
    api.add_argument("--token-file", default="")
    api.add_argument("--path", choices=("health", "snapshot", "policy/confirm"), required=True)
    api.add_argument("--output", required=True)
    summary = commands.add_parser("summarize")
    summary.add_argument("--root", type=Path, required=True)
    return result


def main() -> None:
    arguments = parser().parse_args()
    try:
        if arguments.command == "server":
            run_server(arguments.ready)
        elif arguments.command == "client":
            write_json(arguments.output, run_client(arguments.duration, arguments.legitimate_rate, arguments.background_rate, arguments.target))
        elif arguments.command == "process-cpu":
            write_json(arguments.output, process_cpu(arguments.pid))
        elif arguments.command == "host-cpu":
            with Path("/proc/stat").open(encoding="utf-8") as stream:
                line=stream.readline(4097)
            if len(line)>4096: raise ValueError("aggregate CPU record exceeds its bound")
            write_json(arguments.output,parse_host_cpu(line,os.sysconf("SC_CLK_TCK")))
        elif arguments.command == "api":
            api_call(arguments.token_file, arguments.path, arguments.output)
        elif arguments.command == "summarize":
            summarize(arguments.root)
    except (ValueError, RuntimeError, OSError, urllib.error.URLError) as error:
        raise SystemExit(str(error)) from error


if __name__ == "__main__":
    main()
