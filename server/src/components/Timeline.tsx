import { KIND_ICON, withGaps, type DayGroup } from '@/lib/timeline';

const fmtDay = (d: string) => {
  const today = new Date().toLocaleDateString('sv-SE');
  const [, m, day] = d.split('-');
  return `${Number(m)}/${Number(day)}${d === today ? '（今日）' : ''}`;
};

// Each day shows its most important lines; the rest is folded.
export function Timeline({ groups, days, perDay = 3 }: { groups: DayGroup[]; days: number; perDay?: number }) {
  const rows = withGaps(groups, days);
  return (
    <ol className="space-y-3">
      {rows.map((r, i) =>
        r.type === 'gap' ? (
          <li key={i} className="text-sm text-muted">{r.from === r.to ? fmtDay(r.from) : `${fmtDay(r.from)}〜${fmtDay(r.to)}`}　変化なし</li>
        ) : (
          <li key={i}>
            <div className="text-sm font-semibold">{fmtDay(r.g.day)}</div>
            <ul className="mt-1 space-y-1 text-sm">
              {r.g.items.slice(0, perDay).map((it, j) => (
                <li key={j} className="flex gap-2"><span>{KIND_ICON[it.kind] ?? '・'}</span><span className={`min-w-0 break-words ${it.important ? '' : 'text-muted'}`}>{it.title}</span></li>
              ))}
            </ul>
            {r.g.items.length > perDay && (
              <details className="mt-1 text-sm">
                <summary className="cursor-pointer text-accent">ほか {r.g.items.length - perDay}件</summary>
                <ul className="mt-1 space-y-1">
                  {r.g.items.slice(perDay).map((it, j) => (
                    <li key={j} className="flex gap-2"><span>{KIND_ICON[it.kind] ?? '・'}</span><span className={`min-w-0 break-words ${it.important ? '' : 'text-muted'}`}>{it.title}</span></li>
                  ))}
                </ul>
              </details>
            )}
          </li>
        ),
      )}
    </ol>
  );
}

// Two lines (KEV, critical) over the last N days, drawn as inline SVG.
export interface TrendPoint { day: string; kev: number; critical: number; high: number; medium: number; low: number; live?: boolean }

// Stacked-area trend of open findings by severity, so the scale of the backlog and how far it has been
// cut down over time are visible at a glance. The last point may be a live "today" value (point.live).
export function TrendChart({ points, resolvedTotal }: { points: TrendPoint[]; resolvedTotal?: number }) {
  if (points.length < 2) return <p className="text-sm text-muted">推移は2日分以上のデータがたまると表示されます（毎日スナップショットを記録しています）。</p>;
  const SEV = [
    { k: 'low', c: '#94a3b8', label: '低' },
    { k: 'medium', c: '#eab308', label: '中' },
    { k: 'high', c: '#f97316', label: '高' },
    { k: 'critical', c: '#dc2626', label: '緊急' },
    { k: 'kev', c: '#7f1d1d', label: 'KEV' },
  ] as const;
  const total = (p: TrendPoint) => p.low + p.medium + p.high + p.critical + p.kev;
  const cum = (p: TrendPoint, L: number) => { let s = 0; for (let i = 0; i <= L; i++) s += p[SEV[i].k]; return s; };
  const W = 640, H = 160, P = 26;
  const max = Math.max(1, ...points.map(total));
  const n = points.length;
  const x = (i: number) => P + (i * (W - 2 * P)) / (n - 1);
  const y = (v: number) => H - P - (v / max) * (H - 2 * P);
  const band = (L: number) => {
    const up = points.map((p, i) => `${x(i).toFixed(1)},${y(cum(p, L)).toFixed(1)}`);
    const down = points.map((p, i) => `${x(i).toFixed(1)},${y(L === 0 ? 0 : cum(p, L - 1)).toFixed(1)}`).reverse();
    return `M${up.join(' L')} L${down.join(' L')} Z`;
  };
  const last = points[n - 1];
  const at = (daysBack: number) => points[Math.max(0, n - 1 - daysBack)];
  const d = (back: number) => total(last) - total(at(back));
  const fmtD = (v: number) => (v > 0 ? `+${v}` : `${v}`);
  const peak = Math.max(...points.map(total));
  const liveX = last.live ? x(n - 1) : null;
  return (
    <div className="space-y-2">
      <svg viewBox={`0 0 ${W} ${H}`} className="w-full" style={{ height: 160 }} role="img" aria-label="脆弱性件数の推移（深刻度別の積み上げ）">
        <line x1={P} y1={H - P} x2={W - P} y2={H - P} stroke="var(--line)" />
        {SEV.map((s, L) => <path key={s.k} d={band(L)} fill={s.c} fillOpacity={0.85} stroke="none" />)}
        {liveX !== null && <line x1={liveX} y1={P - 6} x2={liveX} y2={H - P} stroke="var(--muted)" strokeDasharray="3 3" />}
        <text x={P} y={H - 8} fontSize="11" fill="var(--muted)">{points[0].day.slice(5)}</text>
        <text x={W - P} y={H - 8} fontSize="11" fill="var(--muted)" textAnchor="end">{last.live ? '現在' : last.day.slice(5)}</text>
        <text x={P} y={P - 10} fontSize="11" fill="var(--muted)">最大 {peak.toLocaleString()} 件</text>
      </svg>
      <div className="flex flex-wrap items-center gap-x-4 gap-y-1 text-xs">
        {[...SEV].reverse().map((s) => (
          <span key={s.k} className="text-muted"><span className="mr-1 inline-block h-2 w-3 rounded align-middle" style={{ background: s.c }} />{s.label} {last[s.k].toLocaleString()}</span>
        ))}
      </div>
      <div className="flex flex-wrap items-center gap-x-4 gap-y-1 text-xs text-muted">
        <span><b className="text-fg">現在 {total(last).toLocaleString()} 件</b></span>
        <span>前日比 {fmtD(d(1))}</span>
        <span>7日 {fmtD(d(7))}</span>
        <span>30日 {fmtD(d(30))}</span>
        <span>ピーク {peak.toLocaleString()} 件</span>
        {resolvedTotal != null && <span>累計解消 {resolvedTotal.toLocaleString()} 件</span>}
      </div>
    </div>
  );
}

// Tiny inline sparkline (total open findings over time) for a unit/host card — just enough to show the
// direction of travel. Generic: takes a number series, no domain assumptions.
export function SparkLine({ values, className }: { values: number[]; className?: string }) {
  if (values.length < 2) return null;
  const W = 120, H = 24, P = 2;
  const max = Math.max(1, ...values);
  const x = (i: number) => P + (i * (W - 2 * P)) / (values.length - 1);
  const y = (v: number) => H - P - (v / max) * (H - 2 * P);
  const line = values.map((v, i) => `${i ? 'L' : 'M'}${x(i).toFixed(1)},${y(v).toFixed(1)}`).join(' ');
  const area = `${line} L${x(values.length - 1).toFixed(1)},${H - P} L${x(0).toFixed(1)},${H - P} Z`;
  const down = values[values.length - 1] <= values[0];
  const c = down ? '#16a34a' : '#dc2626'; // improving (down) = green, worsening = red
  return (
    <svg viewBox={`0 0 ${W} ${H}`} className={className} style={{ width: W, height: H }} role="img" aria-label="推移" preserveAspectRatio="none">
      <path d={area} fill={c} fillOpacity={0.12} stroke="none" />
      <path d={line} fill="none" stroke={c} strokeWidth="1.5" />
    </svg>
  );
}
