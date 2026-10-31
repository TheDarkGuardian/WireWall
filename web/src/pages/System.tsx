import { useState } from 'react';
import type { FormEvent } from 'react';
import { Check, X, Download, RefreshCw, Save } from 'lucide-react';
import { api } from '../api';
import { number, duration, bytes } from '../format';
import type { Policy, Snapshot } from '../types';
import MonitoringLinks from '../components/MonitoringLinks';

type Perform = (job: () => Promise<unknown>, success: string) => Promise<boolean>;
export default function System({ data, perform, busy }: { data: Snapshot; perform: Perform; busy: boolean }) {
  const [form, setForm] = useState<Policy>(() => structuredClone(data.policy));
  const [tcpPorts, setTcpPorts] = useState(data.policy.host.tcpPorts.join(', '));
  const [udpPorts, setUdpPorts] = useState(data.policy.host.udpPorts.join(', '));
  const [cidrs, setCidrs] = useState(data.policy.managementCidrs.join('\n'));
  const [localError, setLocalError] = useState('');
  const reload = () => { setForm(structuredClone(data.policy)); setTcpPorts(data.policy.host.tcpPorts.join(', ')); setUdpPorts(data.policy.host.udpPorts.join(', ')); setCidrs(data.policy.managementCidrs.join('\n')); setLocalError(''); };
  const parsePorts = (value: string) => {
    const entries = value.trim() ? value.split(',').map(entry => entry.trim()) : [];
    if (entries.some(entry => !/^\d+$/.test(entry) || Number(entry) < 1 || Number(entry) > 65535)) throw new Error('Servis portları 1–65535 arasında olmalı ve virgülle ayrılmalı.');
    return entries.map(Number);
  };
  const save = async (event: FormEvent) => {
    event.preventDefault(); setLocalError('');
    let updated: Policy;
    try { updated = { ...form, managementCidrs: cidrs.split(/[\n,]+/).map(entry => entry.trim()).filter(Boolean), host: { ...form.host, tcpPorts: parsePorts(tcpPorts), udpPorts: parsePorts(udpPorts) } }; }
    catch (err) { setLocalError((err as Error).message); return; }
    let applied: Policy | null = null;
    if (await perform(async () => { await api.validatePolicy(updated); applied = await api.applyPolicy(updated, form.version); }, 'Sistem politikası doğrulandı ve uygulandı.')) {
      setForm(applied!);
    }
  };
  const exportPolicy = () => { const url = URL.createObjectURL(new Blob([JSON.stringify(data.policy, null, 2)], { type: 'application/json' })); const link = document.createElement('a'); link.href = url; link.download = `wirewall-policy-v${data.policy.version}.json`; link.click(); URL.revokeObjectURL(url); };
  const details = [
    ['Çalışma ortamı', data.system.simulated ? 'Laboratuvar / sentetik trafik' : 'Linux XDP'],
    ['Makine', data.system.hostname], ['Platform', data.system.platform],
    ['Arayüz', data.system.interface || '—'], ['XDP bağlantısı', data.system.attached ? data.system.xdpMode : 'Bağlı değil'],
    ['Çalışma süresi', duration(data.system.uptimeSeconds)],
    ['Map kapasite hatası', number(data.metrics.mapCapacityFailures)], ['Olay kayıt kaybı', number(data.metrics.eventDrops)],
  ];
  const resources = data.system.resources;
  const resourceDetails = resources ? [
    ['CPU kullanımı', resources.cpuPercent == null ? '—' : `%${resources.cpuPercent.toLocaleString('tr-TR', { maximumFractionDigits: 1 })}`],
    ['Bellek kullanımı', `${bytes(resources.memoryUsedBytes)} / ${bytes(resources.memoryTotalBytes)}`],
    ['Conntrack doluluğu', `${resources.conntrackCount == null ? '—' : number(resources.conntrackCount)} / ${resources.conntrackMax == null ? '—' : number(resources.conntrackMax)}`],
  ] : [];
  return <><div className="system-grid"><section className="panel"><div className="panel-heading"><h2>Çalışma durumu</h2><span className="muted">v{data.system.version}</span></div><dl className="detail-list">{details.map(([label, value]) => <div key={label}><dt>{label}</dt><dd className="mono">{value}</dd></div>)}</dl></section><section className="panel"><div className="panel-heading"><h2>Özellik desteği</h2></div><div className="capability-list">{data.system.capabilities.length ? data.system.capabilities.map(item => <div key={item.name}><span className={`inline ${item.available ? 'green' : 'muted'}`}>{item.available ? <Check size={17} /> : <X size={17} />}<strong>{item.name}</strong></span><p>{item.detail}</p></div>) : <p className="empty-state compact">Özellik raporu henüz alınmadı.</p>}</div></section></div>
    {data.system.health.length ? <section className="panel"><div className="panel-heading"><h2>Sağlık kontrolleri</h2></div><div className="health-list">{data.system.health.map(item => <div key={item.name}><span className={`dot ${['ok', 'healthy', 'ready'].includes(item.status) ? 'emerald' : 'amber'}`} /><strong>{item.name}</strong><span>{item.detail}</span></div>)}</div></section> : null}
    {resources ? <section className="panel"><div className="panel-heading"><h2>Makine kaynakları</h2><span className="muted">İşletim sistemi ölçümü</span></div>{resources.available ? <><dl className="detail-list">{resourceDetails.map(([label, value]) => <div key={label}><dt>{label}</dt><dd className="mono">{value}</dd></div>)}</dl><p className="panel-footnote">{resources.detail}</p></> : <p className="empty-state compact">{resources.detail || 'Sistem sayaçları bu platformda mevcut değil.'}</p>}</section> : null}
    <MonitoringLinks simulated={data.system.simulated} /><section className="panel form-panel"><div className="panel-heading"><div><h2>Host ve çalışma politikası</h2><p className="muted">Aktif politika sürümü {data.policy.version}. Değişiklikler kaydedilene kadar uygulanmaz.</p></div><button className="button secondary small" onClick={exportPolicy}><Download size={15} /> Dışa aktar</button></div>
      {form.version !== data.policy.version ? <div className="notice">Politika başka bir işlemle değişti. Kaydetmeden önce güncel politikayı yükleyin. <button className="text-button" onClick={reload}><RefreshCw size={14} /> Günceli yükle</button></div> : null}
      <form onSubmit={save}><div className="form-grid">
        <label>Erken filtre modu<select value={form.mode} onChange={event => setForm({ ...form, mode: event.target.value as Policy['mode'] })}><option value="observe">Gözlem — önerilen retleri say</option><option value="enforce">Uygula — eşleşen paketleri düşür</option></select></label>
        <label>Hedef arayüz<input required maxLength={15} value={form.interface} onChange={event => setForm({ ...form, interface: event.target.value })} /></label>
        <label>XDP yükleme modu<select value={form.xdpMode} onChange={event => setForm({ ...form, xdpMode: event.target.value as Policy['xdpMode'] })}><option value="generic">Generic</option><option value="native">Native — sürücü desteği gerekir</option></select></label>
        <label>Yönetim SSH portu<input type="number" required min={1} max={65535} value={form.managementPort} onChange={event => setForm({ ...form, managementPort: Number(event.target.value) })} /></label>
        <label>İzinli TCP servis portları<input value={tcpPorts} onChange={event => setTcpPorts(event.target.value)} placeholder="80, 443" /></label>
        <label>İzinli UDP servis portları<input value={udpPorts} onChange={event => setUdpPorts(event.target.value)} placeholder="53" /></label>
        <label className="span-2">Yönetim CIDR listesi<textarea rows={3} aria-describedby="management-cidr-help" value={cidrs} onChange={event => setCidrs(event.target.value)} placeholder="198.51.100.10/32 veya 2001:db8::10/128" /></label>
        <p id="management-cidr-help" className="notice span-2">Her satıra bir CIDR yazın. Tek IPv4 adresi /32, tek IPv6 adresi /128 ile belirtilir.</p>
        <label className="checkbox-label span-2"><input type="checkbox" checked={form.host.ipv6} onChange={event => setForm({ ...form, host: { ...form.host, ipv6: event.target.checked } })} /> IPv6 host servis politikasını etkinleştir</label>
      </div>{localError ? <p className="form-error" role="alert">{localError}</p> : null}<p className="notice">Host servis izni yeni bağlantıları yönetir. Mevcut akışların davranışı erken filtre ve stateful kural sırasına da bağlıdır.</p><div className="modal-actions"><button type="button" className="button secondary" onClick={reload}>Değişiklikleri sıfırla</button><button className="button primary" disabled={busy || form.version !== data.policy.version}><Save size={16} /> Doğrula ve uygula</button></div></form>
    </section>
  </>;
}
