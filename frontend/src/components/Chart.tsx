import { useId, useState } from "react";

export type Series = { label: string; color: string; values: number[] };

/** Small dependency-free line chart: shared time axis, hover readout, accessible summary. */
export function LineChart({ t, series, format, height = 160, max: fixedMax }: {
  t: number[]; series: Series[]; format: (v: number) => string; height?: number; max?: number;
}) {
  const id = useId(); const [hover, setHover] = useState<number | null>(null);
  const W = 600, H = height, P = { l: 4, r: 4, t: 10, b: 18 };
  if (t.length < 2) return <div className="muted text-sm grid place-items-center" style={{ height }}>Collecting data… the first points appear within a minute.</div>;
  const max = fixedMax ?? Math.max(1, ...series.flatMap((s) => s.values)) * 1.1;
  const x = (i: number) => P.l + (i / (t.length - 1)) * (W - P.l - P.r);
  const y = (v: number) => P.t + (1 - v / max) * (H - P.t - P.b);
  const fmtT = (s: number) => new Date(s * 1000).toLocaleString([], t[t.length - 1] - t[0] > 2 * 86400
    ? { month: "short", day: "numeric" } : { hour: "2-digit", minute: "2-digit" });
  const last = series.map((s) => `${s.label} ${format(s.values[s.values.length - 1])}`).join(", ");
  return <div>
    <div className="flex flex-wrap gap-3 text-xs mb-1">{series.map((s, k) => <span key={s.label} className="flex items-center gap-1.5">
      <span aria-hidden="true" className="inline-block w-3 h-0.5 rounded" style={{ background: s.color }} />{s.label}
      <strong className="tabular-nums">{format(s.values[hover ?? s.values.length - 1] ?? 0)}</strong>{k === 0 && hover != null && <span className="muted">at {fmtT(t[hover])}</span>}</span>)}</div>
    <svg viewBox={`0 0 ${W} ${H}`} className="w-full block" style={{ height }} preserveAspectRatio="none" role="img" aria-label={`Chart, latest: ${last}`}
      onMouseLeave={() => setHover(null)} onMouseMove={(e) => {
        const r = (e.currentTarget as SVGSVGElement).getBoundingClientRect();
        setHover(Math.max(0, Math.min(t.length - 1, Math.round(((e.clientX - r.left) / r.width * W - P.l) / (W - P.l - P.r) * (t.length - 1)))));
      }}>
      <defs>{series.map((s, k) => <linearGradient key={k} id={`${id}-${k}`} x1="0" x2="0" y1="0" y2="1">
        <stop offset="0" stopColor={s.color} stopOpacity=".28" /><stop offset="1" stopColor={s.color} stopOpacity="0" /></linearGradient>)}</defs>
      {[0.25, 0.5, 0.75].map((f) => <line key={f} x1={P.l} x2={W - P.r} y1={y(max * f)} y2={y(max * f)} stroke="var(--border)" vectorEffect="non-scaling-stroke" />)}
      {series.map((s, k) => {
        const pts = s.values.map((v, i) => `${x(i)},${y(v)}`).join(" ");
        return <g key={s.label}>
          {k === 0 && <polygon points={`${x(0)},${y(0)} ${pts} ${x(t.length - 1)},${y(0)}`} fill={`url(#${id}-${k})`} />}
          <polyline points={pts} fill="none" stroke={s.color} strokeWidth="2" vectorEffect="non-scaling-stroke" strokeLinejoin="round" /></g>;
      })}
      {hover != null && <line x1={x(hover)} x2={x(hover)} y1={P.t} y2={H - P.b} stroke="var(--muted)" strokeDasharray="3 3" vectorEffect="non-scaling-stroke" />}
    </svg>
    <div className="flex justify-between muted text-[11px] tabular-nums"><span>{fmtT(t[0])}</span><span>{fmtT(t[Math.floor(t.length / 2)])}</span><span>{fmtT(t[t.length - 1])}</span></div>
  </div>;
}
