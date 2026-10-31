import { ArrowRight } from 'lucide-react';
import { reason, time } from '../format';
import type { PacketEvent } from '../types';

export function Verdict({ action, wouldDrop }: { action: string; wouldDrop?: boolean }) {
  const observedRejection = wouldDrop && action === 'pass';
  return <span className={`verdict ${observedRejection ? 'observe' : action === 'drop' ? 'drop' : 'pass'}`}>{observedRejection ? 'GÖZLEM' : action.toUpperCase()}</span>;
}
export default function EventTable({ events, title = 'Son paket kararları', onAll, historical = false }: { events: PacketEvent[]; title?: string; onAll?: () => void; historical?: boolean }) {
  return <section className="panel table-panel"><div className="panel-heading"><h2>{title}</h2>{onAll ? <button className="text-button" onClick={onAll}>Tümünü görüntüle <ArrowRight size={15} /></button> : <span className="muted">{events.length} kayıt</span>}</div>
    <div className="table-scroll"><table><thead><tr><th>Zaman</th><th>Kaynak</th><th>Hedef / Port</th><th>Protokol</th><th>Karar</th><th>Neden</th>{historical ? <th>Kural / sürüm</th> : null}</tr></thead><tbody>
      {events.length ? events.map(event => <tr key={event.id}><td className="mono muted">{historical ? new Date(event.timestamp).toLocaleString('tr-TR') : time(event.timestamp)}</td><td className="mono">{event.source}<span className="port">:{event.sourcePort}</span></td><td className="mono">{event.destination}<span className="port">:{event.destinationPort}</span></td><td><span className="protocol">{event.protocol.toUpperCase()}</span></td><td><Verdict action={event.action} wouldDrop={event.wouldDrop} /></td><td>{reason(event.reason)}</td>{historical ? <td>{event.ruleId || '—'} · {event.policyVersion ? 'v' + event.policyVersion : 'sürüm bilinmiyor'}</td> : null}</tr>) : <tr><td colSpan={historical ? 7 : 6} className="empty-state">Eşleşen paket kararı yok.</td></tr>}
    </tbody></table></div><div className="panel-footnote">Paket kararı, kurulmuş bir bağlantı sayısı değildir. Olay listesi sınırlı / örneklenmiş olabilir.</div>
  </section>;
}
