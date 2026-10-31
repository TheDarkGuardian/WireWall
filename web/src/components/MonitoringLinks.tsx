import { ExternalLink } from 'lucide-react';

export default function MonitoringLinks({ simulated }: { simulated: boolean }) {
  if (simulated) return null;
  return <section className="panel form-panel"><div className="panel-heading"><div><h2>Grafana izlemesi</h2><p className="muted">Trafik, engelleme, protokol ve sistem kaynaklarının zaman içindeki değişimi.</p></div><a className="button secondary" href="http://localhost:9881/d/wirewall-l4/wirewall" target="_blank" rel="noopener noreferrer"><ExternalLink size={16} /> Grafana'yı aç</a></div><p className="panel-footnote">Ayrı Grafana oturumu ve SSH tüneli gerekir. Metrik geçmişi kurulumdan itibaren birikir. Paket olaylarının filtrelenmiş raporları Olay Geçmişi sayfasındadır.</p></section>;
}
