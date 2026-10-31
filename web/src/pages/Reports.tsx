import { useEffect, useState } from 'react';
import type { FormEvent } from 'react';
import { Download, RefreshCw, ChevronLeft, ChevronRight, FileText, Ban, Eye, Network } from 'lucide-react';
import { api } from '../api';
import EventTable from '../components/EventTable';
import { bytes, number, reason } from '../format';
import type { AuditEntry, EventHistory, NamedCount } from '../types';

type Filters = { from: string; to: string; source: string; destination: string; protocol: string; action: string; port: string; policyVersion: string; ruleId: string; reason: string; q: string };
function initialFilters(): Filters {
  const date = new Date(Date.now() - 24 * 3600_000);
  const local = new Date(date.getTime() - date.getTimezoneOffset() * 60_000).toISOString().slice(0, 16);
  return { from: local, to: '', source: '', destination: '', protocol: '', action: '', port: '', policyVersion: '', ruleId: '', reason: '', q: '' };
}
function search(filters: Filters) {
  const params = new URLSearchParams({ limit: '50' });
  for (const [key, value] of Object.entries(filters)) if (value.trim()) params.set(key, key === 'from' || key === 'to' ? new Date(value).toISOString() : value.trim());
  return params.toString();
}
const stamp = (value: string) => new Date(value).toLocaleString('tr-TR');
const escapeHTML = (value: unknown) => String(value ?? '').replace(/[&<>"']/g, char => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[char]!));
function download(content: Blob, name: string) {
  const url = URL.createObjectURL(content); const link = document.createElement('a'); link.href = url; link.download = name; link.click(); setTimeout(() => URL.revokeObjectURL(url), 1000);
}
function Group({ title, items, translate = false }: { title: string; items: NamedCount[]; translate?: boolean }) {
  const max = Math.max(1, ...items.map(item => item.count));
  return <section className="panel"><div className="panel-heading"><h2>{title}</h2><span className="muted">Filtrelenmiş kayıtlar</span></div><div className="history-groups">{items.length ? items.map(item => <div key={item.label} className="history-group"><div><span>{translate ? reason(item.label) : item.label || 'Bilinmiyor / kural yok'}</span><strong>{number(item.count)}</strong></div><div className="reason-track"><span style={{ width: `${item.count / max * 100}%` }} /></div></div>) : <p className="empty-state compact">Bu aralıkta kayıt yok.</p>}</div></section>;
}
function htmlReport(data: EventHistory, query: string) {
  const labels: Record<string, string> = { source: 'Kaynak IP', destination: 'Hedef IP', protocol: 'Protokol', action: 'Karar', port: 'Hedef port', policyVersion: 'Politika sürümü', ruleId: 'Kural', reason: 'Neden', q: 'Arama' };
  const selected = [...new URLSearchParams(query).entries()].filter(([key]) => labels[key]).map(([key, value]) => `${labels[key]}: ${value}`).join(' · ') || 'Ek filtre yok';
  const groups = (title: string, items: NamedCount[]) => `<h2>${escapeHTML(title)}</h2><table><tr><th>Grup</th><th>Olay kaydı</th></tr>${items.map(item => `<tr><td>${escapeHTML(item.label || 'Bilinmiyor / kural yok')}</td><td>${item.count}</td></tr>`).join('')}</table>`;
  return `<!doctype html><html lang="tr"><meta charset="utf-8"><title>WireWall olay raporu</title><style>body{font:15px/1.6 Arial,sans-serif;max-width:1000px;margin:40px auto;padding:0 24px;color:#17322c}h1,h2{color:#007d60}table{border-collapse:collapse;width:100%;margin:18px 0}td,th{border:1px solid #cdded7;padding:8px;text-align:left;overflow-wrap:anywhere}p{overflow-wrap:anywhere}@media print{body{margin:0}h2{break-after:avoid}tr{break-inside:avoid}}</style><h1>WireWall olay raporu</h1><p><strong>${data.simulated ? 'Sentetik laboratuvar' : 'Gerçek Linux / örneklenmiş paket olayları'}</strong></p><p>Aralık: ${escapeHTML(stamp(data.from))} - ${escapeHTML(stamp(data.to))}<br>Üretim: ${escapeHTML(stamp(data.generatedAt))}<br>Filtreler: ${escapeHTML(selected)}</p><p>Bu rapor tam trafik kaydı veya saldırı sayımı değildir. Aşağıdaki sayılar saklanan olay örneklerine aittir. Saklama: en çok ${data.retentionDays} gün / ${data.recordLimit} kayıt; erken silinen eski veriler geri getirilemez.</p><table><tr><th>Eşleşen kayıt</th><th>DROP</th><th>PASS</th><th>Gözlem önerisi</th><th>Farklı kaynak</th></tr><tr><td>${data.summary.matchedEvents}</td><td>${data.summary.droppedEvents}</td><td>${data.summary.passedEvents}</td><td>${data.summary.wouldDropEvents}</td><td>${data.summary.uniqueSources}</td></tr></table>${groups('Nedenler', data.summary.reasons)}${groups('Protokoller', data.summary.protocols)}${groups('Kaynaklar', data.summary.sources)}${groups('Kurallar', data.summary.rules)}${groups('Saatlik kayıtlar (UTC)', data.summary.timeline)}<h2>Görüntülenen sayfa: ${data.items.length} örnek</h2><p>Özetler bütün eşleşmelere aittir; aşağıdaki tablo yalnız görüntülenen sayfadır.</p><table><tr><th>Zaman</th><th>Kaynak</th><th>Hedef / port</th><th>Karar</th><th>Neden</th><th>Politika</th></tr>${data.items.map(item => `<tr><td>${escapeHTML(stamp(item.timestamp))}</td><td>${escapeHTML(item.source)}:${item.sourcePort}</td><td>${escapeHTML(item.destination)}:${item.destinationPort}</td><td>${escapeHTML(item.wouldDrop && item.action === 'pass' ? 'GÖZLEM' : item.action)}</td><td>${escapeHTML(item.reason)}</td><td>${item.policyVersion || 'Bilinmiyor'}</td></tr>`).join('')}</table></html>`;
}

export default function Reports({ simulated }: { simulated: boolean }) {
  const [draft, setDraft] = useState(initialFilters);
  const [applied, setApplied] = useState(() => search(draft));
  const [cursor, setCursor] = useState(''); const [previous, setPrevious] = useState<string[]>([]);
  const [revision, setRevision] = useState(0); const [data, setData] = useState<EventHistory | null>(null);
  const [loading, setLoading] = useState(true); const [exporting, setExporting] = useState(false);
  const [error, setError] = useState(''); const [notice, setNotice] = useState('');
  const [audit, setAudit] = useState<AuditEntry[]>([]); const [auditError, setAuditError] = useState('');
  useEffect(() => {
    const controller = new AbortController(); const params = new URLSearchParams(applied);
    if (cursor) params.set('cursor', cursor);
    setLoading(true); setError('');
    api.eventHistory(params.toString(), controller.signal).then(value => {
      if (controller.signal.aborted) return;
      if (value.simulated !== simulated) throw new Error('Geçmiş verisinin çalışma ortamı uyuşmuyor.');
      setData(value);
    }).catch(err => { if (!controller.signal.aborted) { setError((err as Error).message); setData(null); } }).finally(() => { if (!controller.signal.aborted) setLoading(false); });
    return () => controller.abort();
  }, [applied, cursor, revision, simulated]);
  useEffect(() => {
    const controller = new AbortController();
    api.audit(controller.signal).then(value => { if (!controller.signal.aborted) { setAudit(value.items); setAuditError(''); } }).catch(err => { if (!controller.signal.aborted) setAuditError((err as Error).message); });
    return () => controller.abort();
  }, [revision]);
  const apply = (event: FormEvent) => {
    event.preventDefault();
    if (loading) return;
    try { const query = search(draft); setLoading(true); setError(''); setNotice(''); setCursor(''); setPrevious([]); setApplied(query); setRevision(value => value + 1); }
    catch { setError('Tarih/saat alanlarını kontrol edin.'); }
  };
  const reset = () => { const value = initialFilters(); setDraft(value); setApplied(search(value)); setCursor(''); setPrevious([]); setLoading(true); setError(''); setNotice(''); setRevision(n => n + 1); };
  const exportData = async (format: 'json' | 'csv') => {
    if (loading || exporting || !data || error) return;
    setExporting(true); setNotice(''); setError('');
    try {
      const params = new URLSearchParams(applied); params.set('format', format); params.set('limit', '10000');
      params.set('from', data.from); params.set('to', data.to);
      const response = await fetch(`/api/v1/events/export?${params}`, { credentials: 'same-origin' });
      if (!response.ok) { const value = await response.json(); throw new Error(value.error || 'Dışa aktarma başarısız.'); }
      const truncated = response.headers.get('X-WireWall-Export-Truncated') === 'true';
      download(await response.blob(), `wirewall-history-${Date.now()}.${format}`);
      setNotice(truncated ? 'İlk 10.000 eşleşen kayıt indirildi. Tamamı için tarih aralığını daraltın veya API imlecini kullanın.' : 'Filtrelenmiş olay kayıtları indirildi.');
    } catch (err) { setError((err as Error).message); } finally { setExporting(false); }
  };
  const update = (key: keyof Filters, value: string) => setDraft(previous => ({ ...previous, [key]: value }));
  const stats = data ? [
    { label: 'Eşleşen olay kaydı', value: data.summary.matchedEvents, icon: FileText },
    { label: 'DROP kaydı', value: data.summary.droppedEvents, icon: Ban },
    { label: 'Gözlem önerisi', value: data.summary.wouldDropEvents, icon: Eye },
    { label: 'Farklı kaynak', value: data.summary.uniqueSources, icon: Network },
  ] : [];
  const timelineMax = Math.max(1, ...(data?.summary.timeline.map(item => item.count) || []));
  return <>
    <section className="panel form-panel"><div className="panel-heading"><div><h2>Geçmiş filtreleri</h2><p className="muted">Saatler tarayıcınızın yerel saat dilimindedir. Boş bitiş alanı şimdiye kadar sorgular.</p></div></div>
      <form onSubmit={apply}><div className="history-filters">
        <label>Başlangıç<input type="datetime-local" aria-label="Geçmiş başlangıç" required value={draft.from} onChange={e => update('from', e.target.value)} /></label>
        <label>Bitiş<input type="datetime-local" aria-label="Geçmiş bitiş" value={draft.to} onChange={e => update('to', e.target.value)} /></label>
        <label>Kaynak IP<input aria-label="Geçmiş kaynak IP" value={draft.source} onChange={e => update('source', e.target.value)} placeholder="Tek IP; boşsa tümü" /></label>
        <label>Hedef IP<input value={draft.destination} onChange={e => update('destination', e.target.value)} placeholder="Tek IP" /></label>
        <label>Karar<select aria-label="Geçmiş karar filtresi" value={draft.action} onChange={e => update('action', e.target.value)}><option value="">Tüm kararlar</option><option value="drop">DROP</option><option value="pass">PASS</option><option value="observe">Gözlem önerisi</option></select></label>
        <label>Protokol<select aria-label="Geçmiş protokol filtresi" value={draft.protocol} onChange={e => update('protocol', e.target.value)}><option value="">Tüm protokoller</option>{['tcp', 'udp', 'icmp', 'icmpv6', 'other'].map(v => <option value={v} key={v}>{v.toUpperCase()}</option>)}</select></label>
        <label>Hedef port<input type="number" min={1} max={65535} value={draft.port} onChange={e => update('port', e.target.value)} /></label>
        <label>Politika sürümü<input type="number" min={1} value={draft.policyVersion} onChange={e => update('policyVersion', e.target.value)} /></label>
        <label>Kural kimliği<input maxLength={80} value={draft.ruleId} onChange={e => update('ruleId', e.target.value)} /></label>
        <label>Neden kodu<input maxLength={64} value={draft.reason} onChange={e => update('reason', e.target.value)} placeholder="rule_drop, source_limit…" /></label>
        <label className="history-wide">Serbest arama<input aria-label="Geçmişte ara" maxLength={120} value={draft.q} onChange={e => update('q', e.target.value)} placeholder="IP, port, kural veya neden" /></label>
      </div><div className="modal-actions"><button type="button" className="button secondary" onClick={reset} disabled={loading}>Son 24 saate dön</button><button className="button primary" disabled={loading}>Filtreleri uygula</button></div></form>
    </section>
    {error ? <div className="error-banner" role="alert">{error}</div> : null}
    {notice ? <div className="info-note" role="status">{notice}</div> : null}
    {loading ? <p role="status" className="notice">Geçmiş sorgulanıyor… {data ? 'Önceki rapor sorgu tamamlanana kadar gösteriliyor.' : ''}</p> : null}
    {data ? <>
      <div className="notice">{data.simulated ? 'Sentetik laboratuvar kayıtları.' : 'Gerçek Linux olay örnekleri; tam trafik veya saldırı sayısı değildir.'} Özetler bütün filtre eşleşmelerini kapsar. En çok {data.retentionDays} gün / {number(data.recordLimit)} kayıt saklanır. Mevcut: {number(data.retainedEvents)}; en eski: {data.oldestAvailable ? stamp(data.oldestAvailable) : 'kayıt yok'}.</div>
      <div className="stats-grid">{stats.map(item => <div className="stat" key={item.label}><item.icon size={24} className="stat-icon green" /><div><div className="stat-label">{item.label}</div><div className="stat-value">{number(item.value)}</div><div className="stat-hint">Seçilen aralıktaki olay örnekleri</div></div></div>)}</div>
      <div className="toolbar"><button className="button secondary" disabled={loading} onClick={() => setRevision(n => n + 1)}><RefreshCw size={16} /> Raporu yenile</button><button className="button secondary" disabled={loading || exporting || !!error} onClick={() => void exportData('json')}><Download size={16} /> Geçmiş JSON</button><button className="button secondary" disabled={loading || exporting || !!error} onClick={() => void exportData('csv')}><Download size={16} /> Geçmiş CSV</button><button className="button secondary" disabled={loading || !!error} onClick={() => download(new Blob([htmlReport(data, applied)], { type: 'text/html;charset=utf-8' }), `wirewall-report-${Date.now()}.html`)}><FileText size={16} /> HTML raporu indir</button></div>
      <p className="panel-footnote">JSON/CSV en çok {number(data.exportLimit)} kayıt içerir; sınır aşılırsa açıkça bildirilir. HTML raporu bütün eşleşmelerin özetini ve görüntülenen sayfayı içerir; tarayıcıdan PDF olarak yazdırılabilir. Üretim: {stamp(data.generatedAt)}. Kayıt byte toplamı: {bytes(data.summary.sampleBytes)}.</p>
      <div className="system-grid"><Group title="Olay nedenleri" items={data.summary.reasons} translate /><Group title="Protokollere göre kayıtlar" items={data.summary.protocols} /><Group title="En çok kaydı olan kaynaklar" items={data.summary.sources} /><Group title="Kurallara göre kayıtlar" items={data.summary.rules} /></div>
      <section className="panel"><div className="panel-heading"><h2>Saatlik olay geçmişi</h2><span className="muted">Olay örnekleri</span></div><div className="history-timeline">{data.summary.timeline.length ? data.summary.timeline.map(item => <div key={item.label}><span>{stamp(item.label)}</span><meter min={0} max={timelineMax} value={item.count} aria-label={`${stamp(item.label)} olay kaydı`} /><strong>{number(item.count)}</strong></div>) : <p className="empty-state compact">Bu aralıkta kayıt yok.</p>}</div></section>
      <EventTable events={data.items} title="Kalıcı olay kayıtları" historical />
      <div className="history-pagination"><button className="button secondary" disabled={loading || !previous.length} onClick={() => { setLoading(true); setCursor(previous[previous.length - 1]); setPrevious(values => values.slice(0, -1)); }}><ChevronLeft size={16} /> Önceki</button><span>Sayfa {previous.length + 1} · {number(data.items.length)} kayıt / {number(data.summary.matchedEvents)} eşleşme</span><button className="button secondary" disabled={loading || !data.hasMore || !!error} onClick={() => { setLoading(true); setPrevious(values => [...values, cursor]); setCursor(data.nextCursor!); }}>Sonraki <ChevronRight size={16} /></button></div>
    </> : null}
    <details className="panel history-audit"><summary>Son 50 yönetim işlemi</summary>{auditError ? <p role="alert">{auditError}</p> : <div className="table-scroll"><table><thead><tr><th>Zaman</th><th>İşlem</th><th>Açıklama</th></tr></thead><tbody>{audit.map(item => <tr key={item.id}><td>{stamp(item.timestamp)}</td><td>{item.action}</td><td>{item.detail}</td></tr>)}</tbody></table></div>}<p className="panel-footnote">Politika, engel ve onay işlemleri; paket olaylarından ayrı denetim kaydıdır. Rapor yenilendiğinde güncellenir.</p></details>
  </>;
}
