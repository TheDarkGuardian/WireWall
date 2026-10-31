import { CircleAlert, ArrowRight } from 'lucide-react';
import { number, time } from '../format';
import type { ScanAlert } from '../types';

export default function ScanAlerts({ alerts, onManage, simulated = false }: { alerts: ScanAlert[] | undefined; onManage: () => void; simulated?: boolean }) {
  if (!alerts) return null;
  const visible = alerts.slice(0, 5);
  if (!visible.length) return <div className="info-note" aria-label="Port taraması uyarıları"><CircleAlert size={17} /><span>Port taraması uyarıları: Henüz şüpheli port taraması uyarısı yok.</span></div>;
  return <section className="panel table-panel scan-alerts" aria-label="Port taraması uyarıları">
    <div className="panel-heading"><div className="inline"><CircleAlert size={18} className="amber-text" /><h2>Şüpheli port taraması</h2></div><button className="text-button" onClick={onManage}>Engelleri görüntüle <ArrowRight size={15} /></button></div>
    {visible.length ? <><div className="table-scroll"><table><thead><tr><th>Zaman / Seviye</th><th>Kaynak → Hedef</th><th>Gözlenen port / Pencere</th><th>Kanıt</th></tr></thead><tbody>{visible.map(alert => <tr key={alert.id}><td><span className="mono muted">{time(alert.timestamp)}</span><div className="cell-detail amber-text">{alert.severity === 'critical' ? 'Kritik' : alert.severity === 'info' ? 'Bilgi' : 'Uyarı'}</div></td><td className="mono">{alert.source}<div className="cell-detail">→ {alert.destination}</div></td><td>{number(alert.uniquePorts)} farklı port<div className="cell-detail">{number(alert.windowSeconds)} sn pencere</div></td><td className="alert-evidence">{alert.message}<div className="cell-detail">{simulated ? 'Sentetik laboratuvar gözlemi' : alert.sampled ? 'Örneklenmiş veri · yaklaşık gözlem' : 'Doğrudan gözlem'}</div></td></tr>)}</tbody></table></div><p className="panel-footnote">Son {visible.length} / {alerts.length} uyarı. Bu sinyal şüpheli davranışı gösterir; otomatik IP engeli uygulanmaz. Örneklenen trafikte port sayısı yaklaşık gözlemdir.</p></> : <p className="empty-state compact">Henüz şüpheli port taraması uyarısı yok.</p>}
  </section>;
}
