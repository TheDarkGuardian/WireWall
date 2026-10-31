import { ArrowDownToLine, Ban, Network, FileText, Clock3 } from 'lucide-react';
import TrafficChart from '../components/TrafficChart';
import EventTable from '../components/EventTable';
import ScanAlerts from '../components/ScanAlerts';
import { number, shortNumber, reason } from '../format';
import type { Page, Snapshot } from '../types';

export default function Overview({ data, navigate }: { data: Snapshot; navigate: (page: Page) => void }) {
  const { metrics, policy } = data;
  const stats = [
    { label: 'Gelen trafik', value: `${shortNumber(metrics.pps)} pps`, hint: 'Anlık paket hızı', icon: ArrowDownToLine, tone: 'green' },
    { label: 'Düşürülen paket', value: number(metrics.droppedPackets), hint: 'Başlangıçtan bu yana', icon: Ban, tone: 'orange' },
    { label: 'Aktif bağlantı', value: number(metrics.activeConnections), hint: data.system.simulated ? 'Sentetik laboratuvar akışları' : 'Gösterilen conntrack akışları (en fazla 256)', icon: Network, tone: 'blue' },
    { label: 'Etkin kural', value: number(policy.rules.filter(rule => rule.enabled).length), hint: `Politika sürümü ${policy.version}`, icon: FileText, tone: 'gray' },
  ];
  const allReasons = metrics.reasons.filter(item => item.count > 0 && !['default_pass', 'default-pass', 'pass', 'rule_pass', 'rule-pass', 'management', 'management_bypass'].includes(item.reason)).sort((a, b) => b.count - a.count);
  const reasons = allReasons.slice(0, 4);
  const total = allReasons.reduce((sum, item) => sum + item.count, 0);
  return <>
    <div className="stats-grid">{stats.map(stat => <div className="stat" key={stat.label}><stat.icon size={27} className={`stat-icon ${stat.tone}`} /><div><div className="stat-label">{stat.label}</div><div className="stat-value">{stat.value}</div><div className="stat-hint">{stat.hint}</div></div></div>)}</div>
    <div className="chart-layout"><TrafficChart points={data.history} /><section className="panel reasons-panel"><div className="panel-heading"><h2>Ret nedenleri</h2><Clock3 size={16} className="muted" /></div><div className="reason-list">{reasons.length ? reasons.map(item => <div className="reason-item" key={item.reason}><div className="reason-top"><span>{reason(item.reason)}</span><strong>{number(item.count)}</strong></div><div className="reason-track"><span style={{ width: `${item.count / total * 100}%` }} /></div><div className="reason-percent">%{Math.round(item.count / total * 100)}</div></div>) : <div className="empty-state compact">Henüz ret nedeni yok.</div>}</div><p className="panel-footnote">İlk dört nedenin tüm nedenler içindeki payı. Gerçek XDP gözlem modunda ret önerileri de dahildir.</p></section></div>
    {policy.mode === 'observe' && metrics.wouldDropPackets > 0 ? <div className="info-note">Gözlem modu: {number(metrics.wouldDropPackets)} paket için ret önerildi; erken katmanda düşürülmedi.</div> : null}
    <ScanAlerts alerts={data.alerts} simulated={data.system.simulated} onManage={() => navigate('bans')} />
    <EventTable events={data.events.slice(0, 5)} onAll={() => navigate('traffic')} />
  </>;
}
