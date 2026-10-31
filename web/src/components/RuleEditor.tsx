import { useEffect, useRef, useState } from 'react';
import type { FormEvent } from 'react';
import { X } from 'lucide-react';
import type { Rule } from '../types';

export default function RuleEditor({ initial, nextPriority, onClose, onSave, error, disabled = false }: { initial: Rule | null; nextPriority: number; onClose: () => void; onSave: (rule: Rule) => Promise<boolean>; error?: string; disabled?: boolean }) {
  const dialog = useRef<HTMLDialogElement>(null);
  const [rule, setRule] = useState<Rule>(() => initial || { id: crypto.randomUUID(), name: '', enabled: true, priority: nextPriority, action: 'drop', protocol: 'tcp', source: 'any', destination: 'any', sourcePort: 'any', destinationPort: 'any', minPacketBytes: 0, maxPacketBytes: 0, pps: 0, burst: 0, sourcePps: 0, sourceBurst: 0, tcpFlags: '' });
  const [saving, setSaving] = useState(false);
  useEffect(() => { dialog.current?.showModal(); }, []);
  const update = <K extends keyof Rule>(key: K, value: Rule[K]) => setRule(previous => ({ ...previous, [key]: value }));
  const numeric = (key: keyof Rule, value: string) => setRule(previous => ({ ...previous, [key]: Number(value) }));
  const changeAction = (action: Rule['action']) => setRule(previous => ({ ...previous, action,
    pps: action === 'limit' ? previous.pps || 100 : 0, burst: action === 'limit' ? previous.burst || 200 : 0,
    sourcePps: action === 'limit' ? previous.sourcePps : 0, sourceBurst: action === 'limit' ? previous.sourceBurst : 0,
    bps: action === 'limit' ? previous.bps || 0 : 0, byteBurst: action === 'limit' ? previous.byteBurst || 0 : 0,
    sourceBps: action === 'limit' ? previous.sourceBps || 0 : 0, sourceByteBurst: action === 'limit' ? previous.sourceByteBurst || 0 : 0 }));
  const changeProtocol = (protocol: Rule['protocol']) => setRule(previous => ({ ...previous, protocol,
    tcpFlags: protocol === 'tcp' ? previous.tcpFlags : '',
    sourcePort: protocol === 'tcp' || protocol === 'udp' ? previous.sourcePort : 'any',
    destinationPort: protocol === 'tcp' || protocol === 'udp' ? previous.destinationPort : 'any' }));
  const submit = async (event: FormEvent) => {
    event.preventDefault();
    if (disabled || saving) return;
    setSaving(true);
    try { if (await onSave(rule)) onClose(); } finally { setSaving(false); }
  };
  return <dialog ref={dialog} className="modal rule-modal" onCancel={onClose} aria-labelledby="rule-title"><form onSubmit={submit}>
    <div className="modal-heading"><div><h2 id="rule-title">{initial ? 'Kuralı düzenle' : 'Yeni kural'}</h2><p>Bir kuralın tüm koşulları birlikte eşleşir. İlk eşleşme uygulanır.</p></div><button type="button" className="icon-button" aria-label="Kapat" onClick={onClose}><X size={20} /></button></div>
    <div className="form-grid">
      <label className="span-2">Kural adı<input autoFocus required maxLength={120} value={rule.name} onChange={event => update('name', event.target.value)} placeholder="Örn. SSH başlangıç sınırı" /></label>
      <label>Öncelik<input type="number" required min={0} max={65535} value={rule.priority} onChange={event => numeric('priority', event.target.value)} /></label>
      <label>Karar<select value={rule.action} onChange={event => changeAction(event.target.value as Rule['action'])}><option value="drop">DROP — düşür</option><option value="pass">PASS — sonraki katmana devret</option><option value="limit">LIMIT — hız sınırı</option></select></label>
      <label>Protokol<select value={rule.protocol} onChange={event => changeProtocol(event.target.value as Rule['protocol'])}>{['any', 'tcp', 'udp', 'icmp', 'icmpv6'].map(value => <option value={value} key={value}>{value === 'any' ? 'Tümü' : value.toUpperCase()}</option>)}</select></label>
      <label>TCP bayrak koşulu<select value={rule.tcpFlags || ''} disabled={rule.protocol !== 'tcp'} onChange={event => update('tcpFlags', event.target.value)}><option value="">Yok</option><option value="syn">SYN başlangıcı</option></select></label>
      <label>Kaynak CIDR<input required aria-describedby="rule-cidr-help" value={rule.source} onChange={event => update('source', event.target.value)} placeholder="any / 198.51.100.0/24" /></label>
      <label>Hedef CIDR<input required aria-describedby="rule-cidr-help" value={rule.destination} onChange={event => update('destination', event.target.value)} placeholder="any / 10.0.0.10/32" /></label>
      <p id="rule-cidr-help" className="notice span-2">CIDR veya any kullanın. Tek IPv4 adresi için /32, tek IPv6 adresi için /128 ekleyin.</p>
      <label>Kaynak port<input required value={rule.sourcePort} onChange={event => update('sourcePort', event.target.value)} placeholder="any / 1024-65535" /></label>
      <label>Hedef port<input required value={rule.destinationPort} onChange={event => update('destinationPort', event.target.value)} placeholder="any / 443 / 80-90" /></label>
      <label>En az paket boyu (byte)<input type="number" min={0} max={65535} value={rule.minPacketBytes} onChange={event => numeric('minPacketBytes', event.target.value)} /></label>
      <label>En fazla paket boyu (0: sınırsız)<input type="number" min={0} max={65535} value={rule.maxPacketBytes} onChange={event => numeric('maxPacketBytes', event.target.value)} /></label>
      {rule.action === 'limit' ? <><div className="form-section span-2">Toplam servis bütçesi</div><label>Paket / saniye<input type="number" required min={1} max={1_000_000_000} value={rule.pps} onChange={event => numeric('pps', event.target.value)} /></label><label>Burst kapasitesi<input type="number" required min={1} max={1_000_000_000} value={rule.burst} onChange={event => numeric('burst', event.target.value)} /></label><div className="form-section span-2">Kaynak IP paket bütçesi <span className="muted">(0: kapalı)</span></div><label>Kaynak başına paket / saniye<input type="number" min={0} max={1_000_000_000} value={rule.sourcePps || 0} onChange={event => numeric('sourcePps', event.target.value)} /></label><label>Kaynak burst kapasitesi<input type="number" min={0} max={1_000_000_000} value={rule.sourceBurst || 0} onChange={event => numeric('sourceBurst', event.target.value)} /></label><div className="form-section span-2">Byte bütçeleri <span className="muted">(0: kapalı; paket sınırına ek)</span></div><label>Servis hızı (byte/s)<input type="number" min={0} max={1_000_000_000} value={rule.bps || 0} onChange={event => numeric('bps', event.target.value)} /></label><label>Servis byte burst (byte)<input type="number" min={0} max={1_000_000_000} value={rule.byteBurst || 0} onChange={event => numeric('byteBurst', event.target.value)} /></label><label>Kaynak IP hızı (byte/s)<input type="number" min={0} max={1_000_000_000} value={rule.sourceBps || 0} onChange={event => numeric('sourceBps', event.target.value)} /></label><label>Kaynak IP byte burst (byte)<input type="number" min={0} max={1_000_000_000} value={rule.sourceByteBurst || 0} onChange={event => numeric('sourceByteBurst', event.target.value)} /></label><p className="notice span-2">Byte/s alanları saniyedeki byte sayısını kullanır. Hız ve burst çifti birlikte sıfır veya birlikte pozitif olmalıdır.</p></> : null}
      <label className="checkbox-label span-2"><input type="checkbox" checked={rule.enabled} onChange={event => update('enabled', event.target.checked)} /> Kural etkin</label>
    </div><p className="notice">XDP engeli mevcut akış paketlerini de kesebilir. PASS, host firewall kabulü anlamına gelmez.</p>
    {error ? <div className="form-error" role="alert">{error}</div> : null}<div className="modal-actions"><button type="button" className="button secondary" onClick={onClose}>Vazgeç</button><button className="button primary" disabled={disabled || saving}>{saving ? 'Doğrulanıyor…' : 'Doğrula ve uygula'}</button></div>
  </form></dialog>;
}
