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
