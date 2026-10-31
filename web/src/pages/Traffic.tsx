import { useMemo, useState } from 'react';
import { Search, Download } from 'lucide-react';
import TrafficChart from '../components/TrafficChart';
import TrafficSummary from '../components/TrafficSummary';
import EventTable from '../components/EventTable';
import { number } from '../format';
import type { Snapshot } from '../types';

export default function Traffic({ data }: { data: Snapshot }) {
  const [query, setQuery] = useState('');
  const [action, setAction] = useState('all');
  const [protocol, setProtocol] = useState('all');
  const filtered = useMemo(() => data.events.filter(event => (action === 'all' || (action === 'observe' ? event.wouldDrop && event.action === 'pass' : event.action === action)) && (protocol === 'all' || event.protocol.toLowerCase() === protocol) && `${event.source} ${event.destination} ${event.sourcePort} ${event.destinationPort} ${event.ruleId || ''} ${event.reason}`.toLowerCase().includes(query.toLowerCase())), [data.events, query, action, protocol]);
  const download = (format: 'json' | 'csv') => {
    const csvCell = (value: unknown) => {
      const text = String(value ?? '');
      const safe = /^\s*[=+\-@]/.test(text) || /^[\t\r\n]/.test(text) ? `'${text}` : text;
      return `"${safe.replaceAll('"', '""')}"`;
    };
    const fields = ['timestamp', 'source', 'destination', 'sourcePort', 'destinationPort', 'protocol', 'length', 'action', 'reason', 'ruleId', 'wouldDrop', 'simulated', 'policyVersion'] as const;
    const content = format === 'json'
      ? JSON.stringify({ simulated: data.system.simulated, exportedAt: new Date().toISOString(), events: filtered }, null, 2)
      : '\ufeff' + [fields.join(','), ...filtered.map(event => fields.map(field => csvCell(event[field])).join(','))].join('\r\n');
    const blob = new Blob([content], { type: format === 'json' ? 'application/json' : 'text/csv;charset=utf-8' });
    const url = URL.createObjectURL(blob); const anchor = document.createElement('a');
    anchor.href = url; anchor.download = `wirewall-events-${Date.now()}.${format}`; anchor.click(); URL.revokeObjectURL(url);
  };
  return <><TrafficChart points={data.history} /><TrafficSummary metrics={data.metrics} simulated={data.system.simulated} /><div className="toolbar"><div className="search-field"><Search size={17} /><input aria-label="Paket kararlarında ara" placeholder="IP, port, neden veya kural ara…" value={query} onChange={event => setQuery(event.target.value)} /></div><select aria-label="Karar filtresi" value={action} onChange={event => setAction(event.target.value)}><option value="all">Tüm kararlar</option><option value="drop">DROP</option><option value="pass">PASS</option><option value="observe">Gözlem</option></select><select aria-label="Protokol filtresi" value={protocol} onChange={event => setProtocol(event.target.value)}><option value="all">Tüm protokoller</option><option value="tcp">TCP</option><option value="udp">UDP</option><option value="icmp">ICMP</option><option value="icmpv6">ICMPv6</option></select><button className="button secondary" onClick={() => download('json')} disabled={!filtered.length}><Download size={16} /> JSON indir</button><button className="button secondary" onClick={() => download('csv')} disabled={!filtered.length}><Download size={16} /> CSV indir</button></div><EventTable events={filtered} title="Paket kararları" /><div className="metrics-strip"><span>Alınan: <strong>{number(data.metrics.receivedPackets)}</strong></span><span>Geçirilen: <strong>{number(data.metrics.passedPackets)}</strong></span><span>Gözlemde ret önerisi: <strong>{number(data.metrics.wouldDropPackets)}</strong></span><span>Kayıt kaybı: <strong>{number(data.metrics.eventDrops)}</strong></span></div></>;
}
