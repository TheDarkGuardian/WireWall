import type { Metrics } from '../types';
import { number, bytes } from '../format';

export default function TrafficSummary({ metrics, simulated }: { metrics: Metrics; simulated: boolean }) {
  const host = metrics.hostFirewall;
  return <>
    <div className="system-grid">
      <section className="panel"><div className="panel-heading"><h2>Protokol dağılımı</h2><span className="muted">{simulated ? 'Sentetik' : 'Örneklenmeyen XDP sayacı'}</span></div>
        <dl className="detail-list">{metrics.protocols.map(item => <div key={item.protocol}><dt>{item.protocol.toUpperCase()}</dt><dd>{number(item.packets)} paket</dd></div>)}</dl>
        {!metrics.protocols.length ? <p className="empty-state compact">Henüz protokol sayacı yok.</p> : null}
      </section>
      <section className="panel"><div className="panel-heading"><h2>Hedef servis portları</h2><span className="muted">İlk 20</span></div>
        <dl className="detail-list">{metrics.services.slice(0, 20).map(item => <div key={`${item.protocol}/${item.port}`}><dt>{item.protocol.toUpperCase()} / {item.port}</dt><dd>{number(item.packets)} paket</dd></div>)}</dl>
        {!metrics.services.length ? <p className="empty-state compact">Henüz servis trafiği yok.</p> : null}
        <p className="panel-footnote">Hedef port uygulamanın çalıştığını göstermez. {simulated ? 'Laboratuvar verisi.' : `1024 port/protokol kapasitesi; sayılmayan servis paketi: ${number(metrics.serviceStatsOverflow || 0)}.`}</p>
      </section>
    </div>
    {!simulated ? <section className="panel"><div className="panel-heading"><h2>Stateful host kararları</h2><span className="muted">nftables / XDP sonrası</span></div>
      {host?.available ? <><div className="metrics-strip"><span>Kabul: <strong>{number(host.acceptedPackets)} paket / {bytes(host.acceptedBytes)}</strong></span><span>Ret: <strong>{number(host.droppedPackets)} paket / {bytes(host.droppedBytes)}</strong></span></div>
        <dl className="detail-list">{host.rules.map((item, index) => <div key={`${item.reason}/${index}`}><dt>{item.reason} · {item.verdict.toUpperCase()}</dt><dd>{number(item.packets)}</dd></div>)}</dl>
        <p className="panel-footnote">Son okuma: {new Date(host.observedAt).toLocaleString('tr-TR')}. Politika yeniden uygulandığında bu sayaçlar sıfırlanır. Host kabulü, uygulama yanıtı garantisi değildir.</p></> : <p className="empty-state compact">{host?.error || 'Host sayaçları bekleniyor.'}</p>}
    </section> : null}
  </>;
}
