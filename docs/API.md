# WireWall HTTP API v1

All endpoints except `GET /api/v1/health`, `GET/POST /api/v1/session` require an authenticated session. The operator token is supplied at startup/file, exchanged using `POST /api/v1/session {"token":"..."}` for an HttpOnly SameSite=Strict cookie. Session responses are `{authenticated:true,csrfToken:"..."}`. Mutations require `X-WireWall-CSRF`. A bearer operator token is supported for CLI calls; it must never be persisted by the browser. Responses use JSON; errors `{error:string}`. No permissive CORS. Browser API requests same origin via Go static host or Vite proxy.

## Snapshot

`GET /api/v1/snapshot`, `GET /api/v1/stream` (SSE `event: snapshot`, same JSON every second):

```
{
 system: {name,version,backend:"lab"|"xdp",platform,hostname,interface,xdpMode,
   attached:boolean,mode:"observe"|"enforce",policyVersion:number,startedAt:string,
   uptimeSeconds:number,simulated:boolean,scenario:string,
   activationPending:boolean,activationDeadline:string,
   resources:{available:boolean,detail:string,cpuPercent:number|null,
     memoryUsedBytes:number|null,memoryTotalBytes:number|null,
     conntrackCount:number|null,conntrackMax:number|null},
   capabilities:[{name,available:boolean,detail}],health:[{name,status,detail}]},
 metrics: {receivedPackets,passedPackets,droppedPackets,wouldDropPackets,
   receivedBytes,pps,bps,dropPps,activeConnections,blockedSources,
   mapCapacityFailures,eventDrops,
   reasons:[{reason,count}],protocols:[{protocol,packets}],
   services:[{port:number,protocol,packets}]},
 history:[{timestamp:string,pps,bps,dropPps}],
 rules:Rule[], bans:Ban[], events:Event[], connections:Connection[], policy:Policy,
 alerts:[{id,timestamp,source,destination,type,severity,message,uniquePorts,windowSeconds,sampled}]
}
```

Event: `{id,policyVersion?,timestamp,source,destination,sourcePort,destinationPort,protocol,length,action,reason,ruleId?,wouldDrop,simulated}`. `policyVersion` records the decision generation; historical rows without it remain unspecified. `wouldDrop` means an early rejection proposed in observe mode, not an enforced early drop. Connection: `{id,source,destination,sourcePort,destinationPort,protocol,state,direction,packets,bytes,accountingAvailable,observedAt,simulated}`. `observedAt` is the last control-plane observation, not an asserted last packet timestamp. Real connection rows/counts represent at most 256 displayed conntrack entries; accounting unavailable must not be displayed as measured zero traffic.

Rules/policy types in `internal/model/model.go` are canonical. A Rule contains `id,name,enabled,priority,action,protocol,source,destination,sourcePort,destinationPort,minPacketBytes,maxPacketBytes,pps,burst,sourcePps,sourceBurst,bps?,byteBurst?,sourceBps?,sourceByteBurst?,tcpFlags`. Port fields accept `any`, one decimal port, or a hyphen range. `source/destination` accept `any` or CIDR; a single IPv4 address uses `/32`, a single IPv6 address `/128`. `pps/burst` is aggregate and mandatory for a limit rule; `sourcePps/sourceBurst` is the optional per-source packet budget. Byte pairs are optional, both zero/absent or both positive, at most 1e9; source-byte limiting also works without a source packet limit. **Rule bps/sourceBps are bytes/second and byteBurst/sourceByteBurst are bytes. Metrics bps is bits/second.** IP packet length is charged; wire overhead is not included.

Scan alerts observe unique TCP destination ports for each source/destination address pair. Defaults: 20 distinct ports in 10 seconds, 30-second cooldown, 1024 tracked pairs and 100 retained warnings. They are suspicions, never proven attacks, and do not automatically ban a source. `sampled=true` means kernel event samples may omit other traffic; no exhaustive detection claim is made. Laboratory warnings are synthetic like the rest of the laboratory snapshot.

Ban: `{id,address,reason,createdAt,expiresAt}`. Timestamps are RFC3339 UTC.

## Policy and bans

- `GET /api/v1/policy` → Policy.
- `POST /api/v1/policy/validate {policy:Policy}` → `{valid:true}` or 422.
- `PUT /api/v1/policy {policy:Policy,expectedVersion:number}` → updated Policy. Optimistic concurrency: stale version returns 409. Successful updates increment server version.
- `POST /api/v1/policy/confirm {}` → `{ok:true}`. Real XDP startup/mutations have an independent 90-second rollback watchdog. `system.activationPending` and `system.activationDeadline` expose it. Confirm only after a fresh SSH connection and service health checks; pending activation prevents further mutations. Laboratory mode has no activation confirmation.
- `POST /api/v1/bans {address:string,reason:string,durationSeconds:number}` → created Ban. Duration 1..86400 seconds; maximum 4096 active bans. Management addresses are protected.
- `DELETE /api/v1/bans/:id` → `{ok:true}` or 404.
- `GET /api/v1/audit?limit=100` → `{items:[{id,timestamp,action,detail}]}`.

## Laboratory (only backend=lab)

- `POST /api/v1/lab/scenarios {scenario:"normal"|"syn-burst"|"udp-burst"|"port-scan"|"mixed"}` → `{scenario:string}`.
- `POST /api/v1/lab/reset {}` → `{ok:true}`. Resets counters/events/lab flows; preserves policy/bans/audit.

Lab data is synthetic and passed through the policy evaluator. It does not send network traffic or protect the host. The UI must label laboratory mode at all times and avoid calling sample events real attacks.

The real backend must fail startup if Linux/XDP prerequisites are missing. No automatic fallback from a requested real backend to simulation.

## Persistent event history

`GET /api/v1/events` uses the authenticated session and current backend provenance (lab vs real). Filters: `from`, `to` RFC3339, exact-IP `source`/`destination`, `protocol`, `action=pass|drop|observe`, destination `port`, `ruleId`, `reason`, `policyVersion`, literal `q`, `limit`1..200(default100), `cursor`. Maximum interval30days; default last24hours. Cursor binds filters/provenance and a fixed cutoff, ordered by timestamp/id descending. Preserve the original query while advancing nextCursor. Invalid/unknown/duplicate filters400, database failure500, four-second query deadline503.

Response: `{items:Event[],summary:{matchedEvents,passedEvents,droppedEvents,wouldDropEvents,sampleBytes,uniqueSources,protocols,reasons,sources,rules,timeline},hasMore,nextCursor?,from,to,generatedAt,simulated,sampled,retentionDays,recordLimit,retainedEvents,oldestAvailable?,exportLimit}`. Named groups are `{label,count}`. Summary covers all matching retained rows, independent of page; timeline is hourlyUTC. Global SQLite retention30days/100000events (whichever bound first), audit5000. Existing pruned records cannot be recovered.

`GET /api/v1/events/export?format=json|csv` accepts the same filters with limit1..10000(default10000). Headers: `X-WireWall-Matched-Events`, `X-WireWall-Export-Truncated`, `X-WireWall-Export-Limit`, and when applicable `X-WireWall-Next-Cursor`. JSON retains summary/hasMore/nextCursor metadata. CSV has UTF-8 BOM, formula-safe cells, policyVersion column; legacy unknown generation is blank. Truncation must be shown to the user. UI HTML report contains the entire filtered summary plus the visible page, with escaped text.

Snapshot additionally exposes `system.observedAt`, `metrics.serviceStatsOverflow`, and `metrics.hostFirewall:{available,error?,observedAt,acceptedPackets,droppedPackets,acceptedBytes,droppedBytes,rules:[{reason,verdict,packets,bytes}]}`. Check the Go JSON types as canonical. Protocol/service counters come from kernel maps; nft counts belong to the subsequent host-input layer and must not be added to XDP counts.

## Prometheus exporter

`wirewall metrics --socket /run/wirewall/control.sock --listen 127.0.0.1:9878` serves only read-only `/metrics` and `/health`. It reads the trusted Unix agent, requires no operator token and exposes no management routes. Intended behind loopback, not a public authenticated proxy. Labels avoid sourceIP, ruleID and policyVersion cardinality. `wirewall_up=0` for unavailable/stale observation (older than10s); real healthy requires attachedXDP and nft counters available. Stale packet counters are omitted. `wirewall_info` mode/backend labels, packet/byte/reason/protocol/service totals, resource gauges and event/map-capacity faults support the provisioned dashboard. Prometheus scrape up must also be checked to avoid stale health.
