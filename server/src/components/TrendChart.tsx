'use client';
// Interactive vulnerability-trend chart: a severity-stacked area over time with a hover tooltip (exact
// per-day counts, so small changes are readable even at a 20k+ scale), an enlarge overlay, legend
// toggles and a range selector. Generic / dependency-free (inline SVG); reused on the home page, the
// host page, and from the per-unit sparklines.
import { useEffect, useState, type PointerEvent as ReactPointerEvent, type ReactNode } from 'react';

export interface TrendPoint { day: string; kev: number; critical: number; high: number; medium: number; low: number; live?: boolean }

type SevKey = 'low' | 'medium' | 'high' | 'critical' | 'kev';
const SEV: { k: SevKey; c: string; label: string }[] = [
  { k: 'low', c: '#94a3b8', label: '低' },
  { k: 'medium', c: '#eab308', label: '中' },
  { k: 'high', c: '#f97316', label: '高' },
  { k: 'critical', c: '#dc2626', label: '緊急' },
  { k: 'kev', c: '#7f1d1d', label: 'KEV' },
];

const fmtDay = (d: string, live?: boolean) => {
  if (live) return '現在';
  const [, m, day] = d.split('-');
  return `${Number(m)}/${Number(day)}`;
};

// Pure SVG stacked area with a hover guide + HTML tooltip. No text in the SVG (labels are HTML) so it can
// stretch to any width with preserveAspectRatio="none" and stay crisp.
function StackedChart({ points, hidden, height }: { points: TrendPoint[]; hidden: Set<SevKey>; height: number }) {
  const [hi, setHi] = useState<number | null>(null);
  const vis = SEV.filter((s) => !hidden.has(s.k));
  const total = (p: TrendPoint) => vis.reduce((a, s) => a + p[s.k], 0);
  const n = points.length;
  const W = 640, H = height, P = 6;
  const max = Math.max(1, ...points.map(total));
  const x = (i: number) => P + (i * (W - 2 * P)) / Math.max(1, n - 1);
  const y = (v: number) => H - P - (v / max) * (H - 2 * P);
  const cum = (p: TrendPoint, L: number) => { let s = 0; for (let i = 0; i <= L; i++) s += p[vis[i].k]; return s; };
  const band = (L: number) => {
    const up = points.map((p, i) => `${x(i).toFixed(1)},${y(cum(p, L)).toFixed(1)}`);
    const down = points.map((p, i) => `${x(i).toFixed(1)},${y(L === 0 ? 0 : cum(p, L - 1)).toFixed(1)}`).reverse();
    return `M${up.join(' L')} L${down.join(' L')} Z`;
  };
  const onMove = (e: ReactPointerEvent<HTMLDivElement>) => {
    const w = e.currentTarget.clientWidth || 1;
    const vx = (e.nativeEvent.offsetX / w) * W;
    const idx = Math.round(((vx - P) / Math.max(1, W - 2 * P)) * (n - 1));
    setHi(Math.max(0, Math.min(n - 1, idx)));
  };
  const hp = hi != null ? points[hi] : null;
  const leftPct = hi != null ? Math.max(8, Math.min(92, (x(hi) / W) * 100)) : 0;
  return (
    <div className="relative w-full select-none" style={{ height: H }}>
      <svg viewBox={`0 0 ${W} ${H}`} className="block h-full w-full" preserveAspectRatio="none" role="img" aria-label="脆弱性件数の推移（深刻度別の積み上げ）">
        <line x1={P} y1={H - P} x2={W - P} y2={H - P} stroke="var(--line)" vectorEffect="non-scaling-stroke" />
        {vis.map((s, L) => <path key={s.k} d={band(L)} fill={s.c} fillOpacity={0.85} stroke="none" />)}
        {hp && <>
          <line x1={x(hi!)} y1={P} x2={x(hi!)} y2={H - P} stroke="var(--fg)" strokeOpacity={0.5} strokeDasharray="3 3" vectorEffect="non-scaling-stroke" />
          <circle cx={x(hi!)} cy={y(total(hp))} r={3.5} fill="var(--fg)" vectorEffect="non-scaling-stroke" />
        </>}
      </svg>
      {/* transparent hover surface */}
      <div className="absolute inset-0 cursor-crosshair" onPointerMove={onMove} onPointerLeave={() => setHi(null)} />
      {hp && (
        <div className="pointer-events-none absolute top-1 z-10 w-max max-w-[16rem] -translate-x-1/2 rounded-md border border-line bg-bg/95 px-2 py-1.5 text-xs shadow-lg backdrop-blur" style={{ left: `${leftPct}%` }}>
          <div className="mb-0.5 font-semibold">{fmtDay(hp.day, hp.live)}{hp.live ? '' : `（${hp.day}）`}</div>
          <div className="grid grid-cols-[auto_auto] gap-x-2">
            {[...vis].reverse().map((s) => <span key={s.k} className="contents"><span className="text-muted"><span className="mr-1 inline-block h-2 w-2.5 rounded-sm align-middle" style={{ background: s.c }} />{s.label}</span><span className="text-right font-mono">{hp[s.k].toLocaleString()}</span></span>)}
            <span className="border-t border-line pt-0.5 font-semibold">合計</span><span className="border-t border-line pt-0.5 text-right font-mono font-semibold">{total(hp).toLocaleString()}</span>
            {hi! > 0 && <><span className="text-muted">前日比</span><span className={`text-right font-mono ${total(hp) - total(points[hi! - 1]) > 0 ? 'text-red-600' : 'text-green-600'}`}>{(() => { const d = total(hp) - total(points[hi! - 1]); return d > 0 ? `+${d.toLocaleString()}` : d.toLocaleString(); })()}</span></>}
          </div>
        </div>
      )}
    </div>
  );
}

// The full chart with controls: legend toggles, a range selector and a summary. `compact` trims the chrome
// for the inline card; the enlarge overlay uses the roomy version.
function ChartPanel({ points, resolvedTotal, height, compact }: { points: TrendPoint[]; resolvedTotal?: number; height: number; compact?: boolean }) {
  const [hidden, setHidden] = useState<Set<SevKey>>(new Set());
  const [range, setRange] = useState<number>(90);
  const toggle = (k: SevKey) => setHidden((prev) => { const n = new Set(prev); if (n.has(k)) n.delete(k); else if (n.size < SEV.length - 1) n.add(k); return n; });
  const view = range >= points.length ? points : points.slice(points.length - range);
  const last = view[view.length - 1];
  const totalOf = (p: TrendPoint) => SEV.filter((s) => !hidden.has(s.k)).reduce((a, s) => a + p[s.k], 0);
  if (view.length < 2) return <p className="text-sm text-muted">推移は2日分以上のデータがたまると表示されます。</p>;
  return (
    <div className="space-y-2">
      <div className="flex flex-wrap items-center gap-2 text-xs">
        <span className="text-muted">期間</span>
        {[7, 30, 90].map((r) => <button key={r} type="button" onClick={() => setRange(r)} className={`rounded px-2 py-0.5 ${range === r ? 'bg-accent text-white' : 'bg-bg text-muted hover:text-fg'}`}>{r}日</button>)}
        <span className="ml-auto flex flex-wrap items-center gap-1.5">
          {SEV.map((s) => (
            <button key={s.k} type="button" onClick={() => toggle(s.k)} title="クリックで表示/非表示" className={`rounded px-1.5 py-0.5 ${hidden.has(s.k) ? 'opacity-35' : ''}`} style={{ background: s.c, color: '#fff' }}>{s.label}</button>
          ))}
        </span>
      </div>
      <StackedChart points={view} hidden={hidden} height={height} />
      <div className="flex justify-between text-xs text-muted"><span>{view[0].day.slice(5)}</span><span>{last.live ? '現在' : last.day.slice(5)}</span></div>
      <div className="flex flex-wrap items-center gap-x-4 gap-y-1 text-xs text-muted">
        <span><b className="text-fg">現在 {totalOf(last).toLocaleString()} 件</b></span>
        <span>最大 {Math.max(...view.map(totalOf)).toLocaleString()} 件</span>
        {!compact && resolvedTotal != null && <span>累計解消 {resolvedTotal.toLocaleString()} 件</span>}
        <span className="text-[11px]">グラフにマウス（スマホはタップ）で各日の件数が出ます</span>
      </div>
    </div>
  );
}

function Modal({ title, onClose, children }: { title: string; onClose: () => void; children: ReactNode }) {
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => { if (e.key === 'Escape') onClose(); };
    document.addEventListener('keydown', onKey);
    const prev = document.body.style.overflow;
    document.body.style.overflow = 'hidden';
    return () => { document.removeEventListener('keydown', onKey); document.body.style.overflow = prev; };
  }, [onClose]);
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 p-4" onClick={onClose}>
      <div className="max-h-[90vh] w-full max-w-4xl overflow-auto rounded-lg border border-line bg-bg p-4 shadow-xl" onClick={(e) => e.stopPropagation()}>
        <div className="mb-2 flex items-center gap-2">
          <h3 className="text-sm font-semibold">{title}</h3>
          <button type="button" onClick={onClose} className="btn-ghost ml-auto text-sm">閉じる ✕</button>
        </div>
        {children}
      </div>
    </div>
  );
}

export function TrendChart({ points, resolvedTotal, title = '脆弱性の推移' }: { points: TrendPoint[]; resolvedTotal?: number; title?: string }) {
  const [open, setOpen] = useState(false);
  return (
    <div>
      <div className="mb-1 flex justify-end">
        <button type="button" onClick={() => setOpen(true)} className="btn-ghost text-xs">⤢ 拡大</button>
      </div>
      <ChartPanel points={points} resolvedTotal={resolvedTotal} height={160} compact />
      {open && (
        <Modal title={title} onClose={() => setOpen(false)}>
          <ChartPanel points={points} resolvedTotal={resolvedTotal} height={Math.round(Math.min(560, Math.max(320, (typeof window !== 'undefined' ? window.innerHeight : 700) * 0.55)))} />
        </Modal>
      )}
    </div>
  );
}

// Tiny inline sparkline (total open findings over time). With `detail`, clicking it opens the full
// interactive chart for that unit in an enlarge overlay — same spec as the main chart.
export function SparkLine({ values, className, detail }: { values: number[]; className?: string; detail?: { points: TrendPoint[]; title: string } }) {
  const [open, setOpen] = useState(false);
  if (values.length < 2) return null;
  const W = 120, H = 24, P = 2;
  const max = Math.max(1, ...values);
  const x = (i: number) => P + (i * (W - 2 * P)) / (values.length - 1);
  const y = (v: number) => H - P - (v / max) * (H - 2 * P);
  const line = values.map((v, i) => `${i ? 'L' : 'M'}${x(i).toFixed(1)},${y(v).toFixed(1)}`).join(' ');
  const area = `${line} L${x(values.length - 1).toFixed(1)},${H - P} L${x(0).toFixed(1)},${H - P} Z`;
  const down = values[values.length - 1] <= values[0];
  const c = down ? '#16a34a' : '#dc2626';
  const svg = (
    <svg viewBox={`0 0 ${W} ${H}`} className={className} style={{ width: W, height: H }} role="img" aria-label="推移" preserveAspectRatio="none">
      <path d={area} fill={c} fillOpacity={0.12} stroke="none" />
      <path d={line} fill="none" stroke={c} strokeWidth="1.5" vectorEffect="non-scaling-stroke" />
    </svg>
  );
  if (!detail) return svg;
  return (
    <>
      <button type="button" onClick={() => setOpen(true)} title="クリックで拡大（日次の件数を表示）" className="cursor-pointer">{svg}</button>
      {open && (
        <Modal title={detail.title} onClose={() => setOpen(false)}>
          <ChartPanel points={detail.points} height={Math.round(Math.min(560, Math.max(320, (typeof window !== 'undefined' ? window.innerHeight : 700) * 0.55)))} />
        </Modal>
      )}
    </>
  );
}
