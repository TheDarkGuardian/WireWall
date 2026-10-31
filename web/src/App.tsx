import { useEffect, useRef, useState } from 'react';
import type { FormEvent } from 'react';
import { Shield, LayoutDashboard, Activity, Network, ListFilter, Ban, Settings2, FlaskConical, Play, CircleAlert, Menu, X, LogOut, LoaderCircle, RefreshCw, Check, KeyRound } from 'lucide-react';
import { api } from './api';
import { useWirewall } from './hooks/useWirewall';
import { remaining } from './format';
import Overview from './pages/Overview';
import Traffic from './pages/Traffic';
import Connections from './pages/Connections';
import Rules from './pages/Rules';
import Bans from './pages/Bans';
import System from './pages/System';
import Reports from './pages/Reports';
import type { Page, Scenario } from './types';

const navigation = [
  { id: 'overview' as const, title: 'Genel Bakış', icon: LayoutDashboard, subtitle: 'Paket kararları ve bağlantı durumu' },
  { id: 'traffic' as const, title: 'Canlı Trafik', icon: Activity, subtitle: 'Paket akışı, filtreler ve karar kayıtları' },
  { id: 'reports' as const, title: 'Olay Geçmişi', icon: ListFilter, subtitle: 'Tarih aralığı, kalıcı kayıtlar ve raporlar' },
  { id: 'connections' as const, title: 'Bağlantılar', icon: Network, subtitle: 'Akış durumları ve bağlantı gözlemleri' },
  { id: 'rules' as const, title: 'Kurallar', icon: ListFilter, subtitle: 'Öncelikli Layer 4 erken filtre politikası' },
  { id: 'bans' as const, title: 'Engeller', icon: Ban, subtitle: 'Süreli kaynak IP engelleri' },
  { id: 'system' as const, title: 'Sistem', icon: Settings2, subtitle: 'Çalışma durumu ve host politikası' },
];
const scenarios: { id: Scenario; label: string; detail: string }[] = [
  { id: 'normal', label: 'Normal trafik', detail: 'İzinli servislere düşük oranlı örnek paketler' },
  { id: 'syn-burst', label: 'SYN yoğunluğu', detail: 'TCP başlangıç paketleriyle limiter davranışı' },
  { id: 'udp-burst', label: 'UDP yoğunluğu', detail: 'UDP servis bütçesini aşan sentetik trafik' },
  { id: 'port-scan', label: 'Port taraması', detail: 'Farklı hedef portlara sentetik girişimler' },
  { id: 'mixed', label: 'Karışık trafik', detail: 'Normal ve yoğun trafik örnekleri birlikte' },
];

function Login({ login, error, checking, retry }: { login: (token: string) => Promise<void>; error: string; checking: boolean; retry: () => Promise<void> }) {
  const [token, setToken] = useState(''); const [busy, setBusy] = useState(false); const [message, setMessage] = useState('');
  const submit = async (event: FormEvent) => { event.preventDefault(); const credential = token; setToken(''); setBusy(true); setMessage(''); try { await login(credential); } catch (err) { setMessage((err as Error).message); } finally { setBusy(false); } };
  return <main className="login-page"><div className="login-panel"><div className="brand"><Shield size={34} /><span>WireWall</span></div><h1>Yönetim paneline bağlan</h1><p className="muted">Sunucu başlatılırken verilen operatör anahtarını girin. Anahtar tarayıcı depolamasına kaydedilmez.</p><form onSubmit={submit}><label>Operatör anahtarı<div className="password-field"><KeyRound size={17} /><input autoFocus required type="password" autoComplete="off" spellCheck={false} value={token} onChange={event => setToken(event.target.value)} placeholder="Operatör anahtarınız" /></div></label>{message || error ? <div className="form-error" role="alert">{message || error}</div> : null}<button className="button primary full-width" disabled={busy || checking}>{busy || checking ? <LoaderCircle className="spin" size={17} /> : null}{checking ? 'Oturum kontrol ediliyor…' : busy ? 'Bağlanıyor…' : 'Güvenli oturum aç'}</button></form>{error ? <button className="text-button" onClick={() => void retry()}><RefreshCw size={15} /> Bağlantıyı yeniden dene</button> : null}<div className="login-footer"><FlaskConical size={16} /> Layer 4 firewall geliştirme ve gözlem</div></div></main>;
}
function ScenarioDialog({ current, onClose, onRun, busy }: { current: string; onClose: () => void; onRun: (scenario: Scenario) => Promise<void>; busy: boolean }) {
  const [selected, setSelected] = useState<Scenario>((current || 'normal') as Scenario);
  const dialog = useRef<HTMLDialogElement>(null);
  useEffect(() => { dialog.current?.showModal(); }, []);
  return <dialog ref={dialog} className="modal scenario-modal" onCancel={onClose} aria-labelledby="scenario-title"><div className="modal-heading"><div><h2 id="scenario-title">Laboratuvar senaryosu</h2><p>Yalnız sentetik paket açıklamaları işlenir; ağa trafik gönderilmez.</p></div><button className="icon-button" aria-label="Kapat" onClick={onClose}><X size={20} /></button></div><div className="scenario-options">{scenarios.map(item => <label className={`scenario-option ${selected === item.id ? 'selected' : ''}`} key={item.id}><input type="radio" name="scenario" value={item.id} checked={selected === item.id} onChange={() => setSelected(item.id)} /><div><strong>{item.label}</strong><span>{item.detail}</span></div></label>)}</div><div className="modal-actions"><button className="button secondary" onClick={onClose}>Vazgeç</button><button className="button primary" disabled={busy} onClick={() => void onRun(selected)}><Play size={16} /> Senaryoyu çalıştır</button></div></dialog>;
}

export default function App() {
  const state = useWirewall();
  const [page, setPage] = useState<Page>('overview'); const [mobileOpen, setMobileOpen] = useState(false);
  const [mobileLayout, setMobileLayout] = useState(() => window.matchMedia('(max-width: 760px)').matches);
  const menuButton = useRef<HTMLButtonElement>(null); const sidebar = useRef<HTMLElement>(null);
  const [scenarioOpen, setScenarioOpen] = useState(false); const [busy, setBusy] = useState(false);
  const [notification, setNotification] = useState<{ message: string; error: boolean } | null>(null);
  useEffect(() => { if (!notification) return; const timer = setTimeout(() => setNotification(null), notification.error ? 12000 : 4500); return () => clearTimeout(timer); }, [notification]);
  useEffect(() => {
    const media = window.matchMedia('(max-width: 760px)');
    const update = () => { setMobileLayout(media.matches); if (!media.matches) setMobileOpen(false); };
    media.addEventListener('change', update); return () => media.removeEventListener('change', update);
  }, []);
  useEffect(() => {
    if (!mobileOpen) return;
    const previousOverflow = document.body.style.overflow; document.body.style.overflow = 'hidden';
    sidebar.current?.querySelector<HTMLButtonElement>('button[aria-label="Menüyü kapat"]')?.focus();
    const keyboard = (event: KeyboardEvent) => {
      if (event.key === 'Escape') { event.preventDefault(); setMobileOpen(false); menuButton.current?.focus(); }
      if (event.key === 'Tab') {
        const focusable = sidebar.current?.querySelectorAll<HTMLButtonElement>('button:not(:disabled)');
        if (!focusable?.length) return;
        const first = focusable[0]; const last = focusable[focusable.length - 1];
        if (event.shiftKey && document.activeElement === first) { event.preventDefault(); last.focus(); }
        else if (!event.shiftKey && document.activeElement === last) { event.preventDefault(); first.focus(); }
      }
    };
    document.addEventListener('keydown', keyboard);
    return () => { document.body.style.overflow = previousOverflow; document.removeEventListener('keydown', keyboard); };
  }, [mobileOpen]);
  const perform = async (job: () => Promise<unknown>, success: string, refreshSnapshot = true) => {
    if (busy) return false;
    setBusy(true);
    try { await job(); if (refreshSnapshot) await state.refresh(); setNotification({ message: success, error: false }); return true; }
    catch (err) { setNotification({ message: (err as Error).message, error: true }); if (refreshSnapshot) await state.refresh(); return false; }
    finally { setBusy(false); }
  };
  if (!state.authenticated) return <Login login={state.login} checking={state.checking} error={state.error} retry={state.loadSession} />;
  const navigate = (next: Page) => { const returnFocus = mobileOpen; setPage(next); setMobileOpen(false); if (returnFocus) requestAnimationFrame(() => { const heading = document.querySelector<HTMLElement>('.main-header h1'); if (heading) { heading.tabIndex = -1; heading.focus(); } }); };
  const current = navigation.find(item => item.id === page)!;
  const data = state.snapshot;
  return <div className="app-shell"><a href="#main-content" className="skip-link">İçeriğe geç</a>{mobileOpen ? <button className="sidebar-overlay" aria-label="Menüyü kapat" onClick={() => setMobileOpen(false)} /> : null}
    <aside ref={sidebar} inert={mobileLayout && !mobileOpen} className={`sidebar ${mobileOpen ? 'mobile-open' : ''}`}><div className="brand"><Shield size={34} /><span>WireWall</span><button className="icon-button mobile-close" aria-label="Menüyü kapat" onClick={() => { setMobileOpen(false); menuButton.current?.focus(); }}><X size={20} /></button></div><nav aria-label="Ana gezinme">{navigation.map(item => <button key={item.id} onClick={() => navigate(item.id)} className={`nav-item ${page === item.id ? 'active' : ''}`} aria-current={page === item.id ? 'page' : undefined}><item.icon size={21} /><span>{item.title}</span></button>)}</nav><div className="sidebar-bottom"><div className="environment"><FlaskConical size={19} /><span>{data?.system.simulated ? 'Laboratuvar ortamı' : 'XDP ortamı'}</span><i className={`dot ${state.connected ? 'emerald' : 'amber'}`} /></div><div className="version">WireWall v{data?.system.version || '0.1.0'}</div><button className="logout" onClick={() => void perform(state.logout, 'Oturum kapatıldı.', false)}><LogOut size={16} /> Oturumu kapat</button></div></aside>
    <main id="main-content" className="main-content"><header className="main-header"><div className="header-title"><button ref={menuButton} className="icon-button mobile-menu" aria-label="Menüyü aç" aria-expanded={mobileOpen} onClick={() => setMobileOpen(true)}><Menu size={23} /></button><div><h1>{current.title}</h1><p>{current.subtitle}</p></div></div><div className="header-actions"><span className="api-status"><i className={`dot ${state.connected ? 'emerald' : 'amber'}`} />{state.connected ? 'API bağlı' : 'Yeniden bağlanıyor'}</span>{data?.system.simulated ? <button className="button primary" onClick={() => setScenarioOpen(true)} disabled={busy}><Play size={16} /> Senaryo çalıştır</button> : <button className="button secondary" onClick={() => void state.refresh()}><RefreshCw size={16} /> Yenile</button>}</div></header>
      {data && state.stale ? <div className="mode-banner observe" role="status"><CircleAlert size={18} /><span>Veriler güncel değil. Gösterilen değerler son başarılı gözleme aittir.{state.lastUpdatedAt ? ` Son gözlem: ${new Date(state.lastUpdatedAt).toLocaleString('tr-TR')}.` : ''}{!data.system.simulated ? ' XDP korumasının güncel durumu doğrulanamadı.' : ''}</span></div> : data?.system.simulated ? <div className="lab-banner"><CircleAlert size={18} /><span>Laboratuvar modu — gerçek ağ trafiği filtrelenmiyor.</span><span className="scenario-label">{scenarios.find(item => item.id === data.system.scenario)?.label || data.system.scenario}</span></div> : data ? <div className={`mode-banner ${!data.system.attached ? 'inactive' : data.policy.mode === 'observe' ? 'observe' : ''}`}><Shield size={18} /><span>{!data.system.attached ? 'XDP arayüze bağlı değil; erken filtre koruması doğrulanamadı.' : data.policy.mode === 'observe' ? 'Gözlem modu — XDP ret önerileri sayılır, erken katmanda düşürülmez.' : 'XDP uygulama modu etkin.'}</span></div> : null}
      {data && !data.system.simulated && data.system.activationPending ? <div className="activation-banner" role="alert"><CircleAlert size={20} /><div><strong>Geçici politika onayı bekleniyor</strong><p>Yeni bir SSH oturumuyla erişimi doğruladıktan sonra onaylayın. Onay gelmezse önceki duruma dönülür.{data.system.activationDeadline ? ` Kalan süre: ${remaining(data.system.activationDeadline)}.` : ''}</p></div><button className="button primary" disabled={busy || state.stale} onClick={() => void perform(api.confirmPolicy, 'Geçici politika kalıcılaştırıldı.')}>Erişimi doğruladım, onayla</button></div> : null}
      {state.error ? <div className="error-banner" role="alert"><CircleAlert size={18} />{state.error}<button className="text-button" onClick={() => void state.refresh()}>Yeniden dene</button></div> : null}
      {!data ? <div className="loading-state"><LoaderCircle className="spin" size={28} /><p>Firewall verileri alınıyor…</p></div> : <div className="page-content">{page === 'overview' ? <Overview data={data} navigate={navigate} /> : page === 'traffic' ? <Traffic data={data} /> : page === 'connections' ? <Connections data={data} /> : page === 'rules' ? <Rules data={data} perform={perform} busy={busy || state.stale || !!data.system.activationPending} /> : page === 'bans' ? <Bans data={data} perform={perform} busy={busy || state.stale || !!data.system.activationPending} /> : page === 'reports' ? <Reports simulated={data.system.simulated} /> : <System data={data} perform={perform} busy={busy || state.stale || !!data.system.activationPending} />}</div>}
      <footer className="app-footer"><span>WireWall · Layer 4 trafik kontrolü</span><span>{data ? `Politika v${data.policy.version} · ${data.policy.mode === 'observe' ? 'Gözlem' : 'Uygula'}` : 'Bağlantı bekleniyor'}</span>{data?.system.simulated ? <button className="text-button" disabled={busy} onClick={() => void perform(api.resetLab, 'Laboratuvar sayaçları ve akışları sıfırlandı.')}><RefreshCw size={13} /> Laboratuvarı sıfırla</button> : null}</footer>
    </main>{notification ? <div className={`toast ${notification.error ? 'toast-error' : ''}`} role={notification.error ? 'alert' : 'status'}>{notification.error ? <CircleAlert size={19} /> : <Check size={19} />}<span>{notification.message}</span><button className="icon-button" aria-label="Bildirimi kapat" onClick={() => setNotification(null)}><X size={17} /></button></div> : null}
    {scenarioOpen && data ? <ScenarioDialog current={data.system.scenario} onClose={() => setScenarioOpen(false)} busy={busy} onRun={async scenario => { if (await perform(() => api.scenario(scenario), 'Laboratuvar senaryosu başlatıldı.')) setScenarioOpen(false); }} /> : null}
  </div>;
}
