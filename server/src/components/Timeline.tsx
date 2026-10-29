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
export function TrendChart({ points }: { points: { day: string; kev: number; critical: number }[] }) {
  if (points.length < 2) return <p className="text-sm text-muted">推移は2日分以上のデータがたまると表示されます。</p>;
  const W = 600, H = 140, P = 24;
  const max = Math.max(1, ...points.map((p) => Math.max(p.kev, p.critical)));
  const x = (i: number) => P + (i * (W - 2 * P)) / (points.length - 1);
  const y = (v: number) => H - P - (v / max) * (H - 2 * P);
  const path = (k: 'kev' | 'critical') => points.map((p, i) => `${i ? 'L' : 'M'}${x(i).toFixed(1)},${y(p[k]).toFixed(1)}`).join(' ');
  const last = points[points.length - 1];
  return (
    <div>
      <svg viewBox={`0 0 ${W} ${H}`} className="h-36 w-full" role="img" aria-label="KEVと緊急の推移">
        <line x1={P} y1={H - P} x2={W - P} y2={H - P} stroke="var(--line)" />
        <path d={path('critical')} fill="none" stroke="#f97316" strokeWidth="2.5" />
        <path d={path('kev')} fill="none" stroke="#dc2626" strokeWidth="2.5" />
        <text x={P} y={H - 6} fontSize="11" fill="var(--muted)">{points[0].day.slice(5)}</text>
        <text x={W - P} y={H - 6} fontSize="11" fill="var(--muted)" textAnchor="end">{last.day.slice(5)}</text>
      </svg>
      <div className="flex gap-4 text-xs text-muted">
        <span><span className="mr-1 inline-block h-2 w-3 rounded" style={{ background: '#dc2626' }} />KEV {last.kev}</span>
        <span><span className="mr-1 inline-block h-2 w-3 rounded" style={{ background: '#f97316' }} />緊急 {last.critical}</span>
      </div>
    </div>
  );
}
