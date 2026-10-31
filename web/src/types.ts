export type RuleAction = 'pass' | 'drop' | 'limit';
export type Protocol = 'any' | 'tcp' | 'udp' | 'icmp' | 'icmpv6';
export interface Rule {
  id: string; name: string; enabled: boolean; priority: number;
  action: RuleAction; protocol: Protocol; source: string; destination: string;
  sourcePort: string; destinationPort: string; minPacketBytes: number;
  maxPacketBytes: number; pps: number; burst: number; sourcePps?: number;
  sourceBurst?: number; tcpFlags?: string;
  /** Byte budget units are bytes/second; metrics.bps is bits/second. */
  bps?: number; byteBurst?: number; sourceBps?: number; sourceByteBurst?: number;
}
export interface Policy {
  version: number; mode: 'observe' | 'enforce'; interface: string;
  xdpMode: 'native' | 'generic'; managementCidrs: string[];
  managementPort: number; rules: Rule[];
  host: { tcpPorts: number[]; udpPorts: number[]; ipv6: boolean };
}
export interface Ban { id: string; address: string; reason: string; createdAt: string; expiresAt: string }
export interface PacketEvent {
  id: string; policyVersion?: number; timestamp: string; source: string; destination: string;
  sourcePort: number; destinationPort: number; protocol: string; length: number;
  action: string; reason: string; ruleId?: string; wouldDrop: boolean;
  simulated: boolean;
}
export interface Connection {
  id: string; source: string; destination: string; sourcePort: number;
  destinationPort: number; protocol: string; state: string; direction: string;
  observedAt: string; packets?: number; bytes?: number; accountingAvailable?: boolean; simulated: boolean;
}
export interface HistoryPoint { timestamp: string; pps: number; bps: number; dropPps: number }
export interface SystemInfo {
  name: string; backend: 'lab' | 'xdp'; mode: 'observe' | 'enforce'; hostname: string;
  platform: string; interface: string; xdpMode: string; attached: boolean;
  uptimeSeconds: number; version: string; policyVersion: number; startedAt: string;
  observedAt?: string;
  simulated: boolean; scenario: string;
  activationPending?: boolean; activationDeadline?: string;
  resources?: { available: boolean; detail: string; cpuPercent: number | null;
    memoryUsedBytes: number | null; memoryTotalBytes: number | null;
    conntrackCount: number | null; conntrackMax: number | null };
  capabilities: { name: string; available: boolean; detail: string }[];
  health: { name: string; status: string; detail: string }[];
}
export interface Metrics {
  receivedPackets: number; passedPackets: number; droppedPackets: number;
  wouldDropPackets: number; receivedBytes: number; pps: number; bps: number;
  dropPps: number; activeConnections: number; blockedSources: number;
  mapCapacityFailures: number; eventDrops: number;
  reasons: { reason: string; count: number }[];
  protocols: { protocol: string; packets: number }[];
  services: { port: number; protocol: string; packets: number }[];
  serviceStatsOverflow?: number;
  hostFirewall?: { available: boolean; observedAt: string; acceptedPackets: number; droppedPackets: number;
    acceptedBytes: number; droppedBytes: number; error?: string;
    rules: { reason: string; verdict: string; packets: number; bytes: number }[] };
}
export interface Snapshot {
  system: SystemInfo; metrics: Metrics; history: HistoryPoint[];
  rules: Rule[]; bans: Ban[]; events: PacketEvent[];
  connections: Connection[]; policy: Policy;
  alerts?: ScanAlert[];
}
export interface ScanAlert {
  id: string; timestamp: string; source: string; destination: string;
  uniquePorts: number; windowSeconds: number; sampled: boolean;
  message: string; type: string; severity: string;
}
export interface Session { authenticated: boolean; csrfToken?: string }
export type Page = 'overview' | 'traffic' | 'connections' | 'rules' | 'bans' | 'system' | 'reports';
export interface NamedCount { label: string; count: number }
export interface EventSummary {
  matchedEvents: number; passedEvents: number; droppedEvents: number; wouldDropEvents: number;
  sampleBytes: number; uniqueSources: number; protocols: NamedCount[]; reasons: NamedCount[];
  sources: NamedCount[]; rules: NamedCount[]; timeline: NamedCount[];
}
export interface EventHistory {
  items: PacketEvent[]; summary: EventSummary; hasMore: boolean; nextCursor?: string;
  from: string; to: string; generatedAt: string; simulated: boolean; sampled: boolean;
  retentionDays: number; recordLimit: number; retainedEvents: number; oldestAvailable?: string; exportLimit: number;
}
export interface AuditEntry { id: string; timestamp: string; action: string; detail: string }
export type Scenario = 'normal' | 'syn-burst' | 'udp-burst' | 'port-scan' | 'mixed';
