import { Clock3 } from 'lucide-react';
import { shortNumber, time } from '../format';
import type { HistoryPoint } from '../types';

export default function TrafficChart({ points: history }: { points: HistoryPoint[] }) {
  const points = history.slice(-60);
  // Leave room for the larger mobile SVG labels as well as desktop labels.
  const width = 760, height = 208, left = 76, top = 10, bottom = 180;
  const max = Math.max(10, ...points.map(point => point.pps)) * 1.15;
  const toX = (index: number) => left + index / Math.max(1, points.length - 1) * (width - left - 8);
  const toY = (value: number) => bottom - value / max * (bottom - top);
  const curve = (key: 'pass' | 'drop') => points.map((point, index) => `${index ? 'L' : 'M'}${toX(index).toFixed(1)},${toY(key === 'drop' ? point.dropPps : Math.max(0, point.pps - point.dropPps)).toFixed(1)}`).join(' ');
  const pass = curve('pass'), drop = curve('drop');
  return <section className="panel chart-panel" aria-label="Trafik grafiği">
    <div className="panel-heading"><h2>Trafik akışı</h2><span className="muted inline"><Clock3 size={15} /> Son 60 örnek</span></div>
    {points.length ? <svg className="traffic-chart" viewBox={`0 0 ${width} ${height}`} role="img" aria-label="Geçen ve düşürülen paketlerin saniyelik değişimi">
      <defs><linearGradient id="traffic-fill" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stopColor="#48d99b" stopOpacity=".2" /><stop offset="100%" stopColor="#48d99b" stopOpacity="0" /></linearGradient></defs>
      {[0, 1, 2, 3, 4].map(index => <g key={index}><line x1={left} x2={width - 8} y1={toY(max * index / 4)} y2={toY(max * index / 4)} className="chart-grid" /><text x={left - 9} y={toY(max * index / 4) + 4} textAnchor="end">{shortNumber(max * index / 4)}</text></g>)}
      {points.length > 1 ? <path d={`${pass} L${toX(points.length - 1)},${bottom} L${left},${bottom} Z`} fill="url(#traffic-fill)" /> : null}
      <path d={pass} className="chart-pass" /><path d={drop} className="chart-drop" />
      {points.filter((_, i) => i === 0 || i === points.length - 1 || i === Math.floor(points.length / 2)).map(point => <text key={point.timestamp} x={toX(points.indexOf(point))} y={201} textAnchor={point === points[0] ? 'start' : point === points[points.length - 1] ? 'end' : 'middle'}>{time(point.timestamp)}</text>)}
    </svg> : <div className="chart-empty">İlk trafik örnekleri bekleniyor.</div>}
    <div className="chart-legend"><span><i className="dot emerald" /> Geçen paket (pps)</span><span><i className="dot amber" /> Düşürülen paket (pps)</span></div>
  </section>;
}
