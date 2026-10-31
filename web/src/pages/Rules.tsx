import { useState } from 'react';
import { Plus, Pencil, Trash2, ShieldCheck } from 'lucide-react';
import RuleEditor from '../components/RuleEditor';
import RuleBudget from '../components/RuleBudget';
import { api } from '../api';
import type { Policy, Rule, Snapshot } from '../types';

type Perform = (job: () => Promise<unknown>, success: string) => Promise<boolean>;
export default function Rules({ data, perform, busy }: { data: Snapshot; perform: Perform; busy: boolean }) {
  const [editor, setEditor] = useState<Rule | 'new' | null>(null);
  const [editingPolicy, setEditingPolicy] = useState<Policy | null>(null);
  const [editorError, setEditorError] = useState('');
  const [deleting, setDeleting] = useState<Rule | null>(null);
  const rows = [...data.policy.rules].sort((a, b) => a.priority - b.priority);
  const apply = (policy: Policy, message: string) => perform(async () => { await api.validatePolicy(policy); await api.applyPolicy(policy, policy.version); }, message);
  const save = (rule: Rule) => {
    setEditorError(''); const base = editingPolicy || data.policy;
    const updated = { ...base, rules: editor === 'new' ? [...base.rules, rule] : base.rules.map(old => old.id === rule.id ? rule : old) };
    return perform(async () => { try { await api.validatePolicy(updated); await api.applyPolicy(updated, base.version); } catch (err) { setEditorError((err as Error).message); throw err; } }, 'Kural doğrulandı ve politika uygulandı.');
  };
  const openEditor = (rule: Rule | 'new') => { setEditingPolicy(structuredClone(data.policy)); setEditorError(''); setEditor(rule); };
  const toggle = (rule: Rule) => apply({ ...data.policy, rules: data.policy.rules.map(old => old.id === rule.id ? { ...old, enabled: !old.enabled } : old) }, 'Kural durumu güncellendi.');
  const remove = async () => { if (deleting && await apply({ ...data.policy, rules: data.policy.rules.filter(rule => rule.id !== deleting.id) }, 'Kural kaldırıldı.')) setDeleting(null); };
  return <><div className="page-actions"><p className="muted">Alanlar AND ile eşleşir. Küçük öncelik değeri önce uygulanır.</p><button className="button primary" onClick={() => openEditor('new')} disabled={busy || rows.length >= 64}><Plus size={17} /> Yeni kural</button></div><section className="panel table-panel"><div className="panel-heading"><h2>Erken filtre kuralları</h2><span className="muted">{rows.length} / 64 · sürüm {data.policy.version}</span></div><div className="table-scroll"><table><thead><tr><th>Öncelik / Ad</th><th>Kaynak → Hedef</th><th>Protokol / Port</th><th>Karar / Limit</th><th>Etkin</th><th><span className="sr-only">İşlemler</span></th></tr></thead><tbody>{rows.length ? rows.map(rule => <tr key={rule.id} className={rule.enabled ? '' : 'disabled-row'}><td><span className="priority">{rule.priority}</span><strong>{rule.name}</strong><div className="cell-detail mono">{rule.id.slice(0, 12)}</div></td><td className="mono">{rule.source}<div className="cell-detail">→ {rule.destination}</div></td><td>{rule.protocol.toUpperCase()}{rule.tcpFlags ? ` · ${rule.tcpFlags.toUpperCase()}` : ''}<div className="cell-detail mono">{rule.sourcePort} → {rule.destinationPort}</div></td><td><span className={`verdict ${rule.action === 'drop' ? 'drop' : rule.action === 'limit' ? 'observe' : 'pass'}`}>{rule.action.toUpperCase()}</span><RuleBudget rule={rule} /></td><td><button className={`toggle ${rule.enabled ? 'on' : ''}`} role="switch" aria-checked={rule.enabled} aria-label={`${rule.name} kuralını ${rule.enabled ? 'kapat' : 'aç'}`} disabled={busy} onClick={() => void toggle(rule)}><span /></button></td><td><div className="row-actions"><button className="icon-button" aria-label={`${rule.name} düzenle`} onClick={() => openEditor(rule)} disabled={busy}><Pencil size={16} /></button><button className="icon-button danger" aria-label={`${rule.name} sil`} onClick={() => setDeleting(rule)} disabled={busy}><Trash2 size={16} /></button></div></td></tr>) : <tr><td colSpan={6} className="empty-state">Henüz erken filtre kuralı yok.</td></tr>}</tbody></table></div></section><div className="info-note"><ShieldCheck size={18} /> PASS yalnız sonraki ağ katmanına devreder. Host servis izinleri ve yönetim istisnası Sistem ekranında bulunur.</div>
    {editor ? <RuleEditor key={editor === 'new' ? 'new' : editor.id} initial={editor === 'new' ? null : editor} nextPriority={Array.from({ length: 65 }, (_, index) => index * 10).find(value => !rows.some(rule => rule.priority === value)) || 0} onClose={() => setEditor(null)} onSave={save} error={editorError} disabled={busy} /> : null}
    {deleting ? <div className="confirm-bar" role="alert"><span><strong>{deleting.name}</strong> kuralı silinsin mi?</span><button className="button secondary" onClick={() => setDeleting(null)}>Vazgeç</button><button className="button danger-button" disabled={busy} onClick={() => void remove()}>Kuralı sil</button></div> : null}
  </>;
}
