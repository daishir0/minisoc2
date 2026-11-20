'use client';

import { useState } from 'react';
import { applyLogFilter, type LogFilter } from '@/lib/logfilter';
import { useMask } from '@/components/Mask';
import { pseudo, type MaskKind } from '@/lib/mask';

// Per-target overview table (direct 24h / latest-day numbers). The unit can be toggled between ホスト and
// vhost(アプリ); vhost is available only where an access log is registered. Columns: ログ量 / 脅威 / 3xx / 4xx /
// 5xx / 改ざん / 14日推移. Clicking a row drills its raw logs. Values that don't apply to a unit are null → "—".
export interface SummaryRow {
  key: string; label: string; color: string;
  logs: number; threats: number | null; s3: number; s4: number; s5: number; files: number | null;
  spark: number[]; patch: LogFilter; mask?: MaskKind; maskKey?: string;
}
export interface SummaryUnit { id: string; label: string; rows: SummaryRow[] }

const RESET: LogFilter = { host: '', source: '', cat: '', vhost: '', status: '', rule: '', q: '', day: '' };

export function LogSummary({ units }: { units: SummaryUnit[] }) {
  const [unitId, setUnitId] = useState(units[0]?.id ?? '');
  const masked = useMask();
  const unit = units.find((u) => u.id === unitId) ?? units[0];
  if (!unit) return <p className="text-sm text-muted">集計がありません。</p>;
  const label = (r: SummaryRow) => (masked && r.mask ? pseudo(r.mask, r.maskKey ?? r.label) : r.label);
  const drill = (patch: LogFilter) => applyLogFilter({ ...RESET, ...patch }, { scroll: true });

  const Pill = ({ n, tone }: { n: number | null; tone: 'muted' | 'warn' | 'crit' }) => {
    if (n == null) return <span className="text-muted">—</span>;
    if (n <= 0) return <span className="text-muted">0</span>;
    const cls = tone === 'crit' ? 'bg-red-500/15 text-red-600' : tone === 'warn' ? 'bg-amber-500/15 text-amber-600' : 'text-muted';
    return <span className={`inline-block rounded-full px-1.5 font-bold ${cls}`}>{n.toLocaleString()}</span>;
  };
  const Spark = ({ v, color }: { v: number[]; color: string }) => {
    const W = 66, H = 18, max = Math.max(1, ...v);
    const pts = v.map((x, i) => `${(i / Math.max(1, v.length - 1)) * W},${H - (x / max) * (H - 2) - 1}`).join(' ');
    return <svg viewBox={`0 0 ${W} ${H}`} preserveAspectRatio="none" style={{ width: 66, height: 18 }} aria-hidden="true"><polyline points={pts} fill="none" stroke={color} strokeWidth="1.4" vectorEffect="non-scaling-stroke" /></svg>;
  };

  return (
    <div>
      {units.length > 1 && (
        <div className="mb-3 inline-flex overflow-hidden rounded-full border border-line text-xs">
          {units.map((u) => (
            <button key={u.id} type="button" onClick={() => setUnitId(u.id)} aria-pressed={u.id === unit.id}
              className={`px-3 py-1 ${u.id === unit.id ? 'bg-accent font-bold text-white' : 'text-muted'}`}>{u.label}</button>
          ))}
        </div>
      )}
      {unit.rows.length === 0 ? <p className="text-sm text-muted">この単位で表示できる対象がありません。</p> : (
        <div className="overflow-x-auto"><table className="tbl">
          <thead><tr>
            <th>対象</th><th className="text-right">ログ量</th><th className="text-right">脅威</th>
            <th className="text-right">3xx</th><th className="text-right">4xx</th><th className="text-right">5xx</th>
            <th className="text-right">改ざん</th><th>推移</th>
          </tr></thead>
          <tbody>
            {unit.rows.map((r) => (
              <tr key={r.key} onClick={() => drill(r.patch)} className="cursor-pointer hover:bg-[var(--soft)]">
                <td><span className="inline-flex items-center gap-1.5"><span className="inline-block h-2.5 w-2.5 shrink-0 rounded-sm" style={{ background: r.color }} /><span className="truncate font-mono text-accent">{label(r)}</span></span></td>
                <td className="whitespace-nowrap text-right font-mono">{r.logs.toLocaleString()}</td>
                <td className="text-right font-mono"><Pill n={r.threats} tone="warn" /></td>
                <td className="text-right font-mono"><Pill n={r.s3} tone="muted" /></td>
                <td className="text-right font-mono"><Pill n={r.s4} tone="warn" /></td>
                <td className="text-right font-mono"><Pill n={r.s5} tone={r.s5 >= 50 ? 'crit' : 'warn'} /></td>
                <td className="text-right font-mono"><Pill n={r.files} tone="warn" /></td>
                <td><Spark v={r.spark} color={r.color} /></td>
              </tr>
            ))}
          </tbody>
        </table></div>
      )}
      <p className="mt-2 text-xs text-muted">行クリックでその対象の生ログへ。vhost(アプリ)別はアクセスログの登録がある対象のみ。</p>
    </div>
  );
}
