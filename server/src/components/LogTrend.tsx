'use client';

import { useEffect, useState } from 'react';
import { applyLogFilter, type LogFilter } from '@/lib/logfilter';
import { useMask } from '@/components/Mask';
import { pseudo, type MaskKind } from '@/lib/mask';

// A daily log-volume trend that can be sliced by different dimensions (category / host / vhost) and shown
// either stacked (one chart, composition) or split (one small-multiple per series — "切り分け"). Clicking a
// stacked segment drills into that series + that day; clicking a small multiple or a legend name drills into
// that series. Per-dimension legend hides persist in localStorage. All drills reset the other filter keys so
// nothing stale lingers, then layer the series' own patch (which already carries host/cat context).
export interface TrendSeries { key: string; label: string; color: string; vals: number[]; patch: LogFilter; mask?: MaskKind; maskKey?: string }
export interface TrendDim { id: string; label: string; series: TrendSeries[] }

const RESET: LogFilter = { host: '', source: '', cat: '', vhost: '', status: '', rule: '', q: '', day: '' };
const LS_KEY = 'logs.trendHidden';

export function LogTrend({ days, dims }: { days: string[]; dims: TrendDim[] }) {
  const [dimId, setDimId] = useState(dims[0]?.id ?? '');
  const [mode, setMode] = useState<'stack' | 'split'>('stack');
  const [hidden, setHidden] = useState<Record<string, string[]>>({});
  const [ready, setReady] = useState(false);
  useEffect(() => {
    try { const r = localStorage.getItem(LS_KEY); if (r) setHidden(JSON.parse(r)); } catch { /* ignore */ }
    setReady(true);
  }, []);
  const masked = useMask();
  const dim = dims.find((d) => d.id === dimId) ?? dims[0];
  if (!dim) return <p className="text-sm text-muted">まだ集計がたまっていません。</p>;
  const rseries = dim.series.map((s) => ({ ...s, label: masked && s.mask ? pseudo(s.mask, s.maskKey ?? s.label) : s.label }));
  const hid = new Set(hidden[dim.id] ?? []);
  const toggle = (k: string) => setHidden((prev) => {
    const cur = new Set(prev[dim.id] ?? []); if (cur.has(k)) cur.delete(k); else cur.add(k);
    const next = { ...prev, [dim.id]: [...cur] };
    try { localStorage.setItem(LS_KEY, JSON.stringify(next)); } catch { /* ignore */ }
    return next;
  });
  const drill = (patch: LogFilter, day?: string) => applyLogFilter({ ...RESET, ...patch, ...(day ? { day } : {}) }, { scroll: true });

  const n = days.length;
  const md = (d: string) => { const [, m, dd] = d.split('-'); return `${Number(m)}/${Number(dd)}`; };
  const axisIdx = n > 1 ? [0, Math.floor(n / 3), Math.floor((2 * n) / 3), n - 1].filter((v, i, a) => a.indexOf(v) === i) : [];
  const vis = rseries.filter((s) => !hid.has(s.key));

  return (
    <div>
      <div className="mb-3 flex flex-wrap items-center gap-x-4 gap-y-2 text-xs">
        <span className="inline-flex items-center gap-1">
          <span className="text-muted">単位</span>
          <span className="inline-flex overflow-hidden rounded-full border border-line">
            {dims.map((d) => (
              <button key={d.id} type="button" onClick={() => setDimId(d.id)} aria-pressed={d.id === dim.id}
                className={`px-2.5 py-1 ${d.id === dim.id ? 'bg-accent font-bold text-white' : 'text-muted'}`}>{d.label}</button>
            ))}
          </span>
        </span>
        <span className="inline-flex items-center gap-1">
          <span className="text-muted">表示</span>
          <span className="inline-flex overflow-hidden rounded-full border border-line">
            {([['stack', '積み上げ'], ['split', '分割']] as const).map(([m, lbl]) => (
              <button key={m} type="button" onClick={() => setMode(m)} aria-pressed={mode === m}
                className={`px-2.5 py-1 ${mode === m ? 'bg-accent font-bold text-white' : 'text-muted'}`}>{lbl}</button>
            ))}
          </span>
        </span>
      </div>

      {rseries.length === 0 || n < 2 ? <p className="text-sm text-muted">この単位で表示できる集計がありません。</p> : mode === 'stack' ? (
        <StackChart days={days} series={vis} axisIdx={axisIdx} md={md} n={n} ready={ready} onBar={(s, i) => drill(s.patch, days[i])} />
      ) : (
        <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
          {rseries.map((s) => <MiniChart key={s.key} s={s} onClick={() => drill(s.patch)} />)}
        </div>
      )}

      {mode === 'stack' && (
        <div className="mt-2 flex flex-wrap items-center gap-x-4 gap-y-1.5 text-xs">
          {rseries.map((s) => (
            <span key={s.key} className="inline-flex items-center gap-1.5">
              <input type="checkbox" checked={!hid.has(s.key)} onChange={() => toggle(s.key)} aria-label={`${s.label}を表示`} className="accent-[var(--accent)]" />
              <button type="button" onClick={() => drill(s.patch)} className="inline-flex items-center gap-1 text-muted hover:text-fg">
                <span className="inline-block h-3 w-3 rounded-sm" style={{ background: s.color }} />{s.label}
              </button>
            </span>
          ))}
          <span className="ml-auto text-muted">チェックで表示切替／名前・棒クリックで生ログへ</span>
        </div>
      )}
    </div>
  );
}

function StackChart({ days, series, axisIdx, md, n, ready, onBar }: {
  days: string[]; series: TrendSeries[]; axisIdx: number[]; md: (d: string) => string; n: number; ready: boolean; onBar: (s: TrendSeries, i: number) => void;
}) {
  const totals = days.map((_, i) => series.reduce((a, s) => a + (s.vals[i] || 0), 0));
  const max = Math.max(1, ...totals);
  return (
    <>
      <div className="flex items-end gap-0.5" style={{ height: 150 }} aria-hidden={!ready}>
        {days.map((day, i) => (
          <div key={i} title={`${day}: ${totals[i].toLocaleString()}行`} className="flex flex-1 flex-col justify-end" style={{ maxWidth: 26, height: '100%' }}>
            {series.map((s) => { const h = ((s.vals[i] || 0) / max) * 140; return h > 0.3 ? (
              <div key={s.key} onClick={() => onBar(s, i)} title={`${day} ${s.label} ${(s.vals[i] || 0).toLocaleString()}行 → この日の生ログ`} style={{ height: `${h}px`, background: s.color, cursor: 'pointer' }} />
            ) : null; })}
          </div>
        ))}
      </div>
      <div className="relative mt-1 h-4 text-[10px] text-muted">
        {axisIdx.map((i) => <span key={i} className="absolute -translate-x-1/2" style={{ left: `${(n <= 1 ? 0 : (i / (n - 1)) * 100)}%` }}>{md(days[i])}</span>)}
      </div>
    </>
  );
}

function MiniChart({ s, onClick }: { s: TrendSeries; onClick: () => void }) {
  const max = Math.max(1, ...s.vals);
  const total = s.vals.reduce((a, x) => a + x, 0);
  return (
    <button type="button" onClick={onClick} title={`${s.label} 計${total.toLocaleString()}行 → 生ログ`}
      className="rounded-lg border border-line p-2 text-left hover:border-accent">
      <div className="flex items-center gap-1.5 text-xs">
        <span className="inline-block h-2.5 w-2.5 rounded-sm" style={{ background: s.color }} />
        <span className="truncate font-mono">{s.label}</span>
        <span className="ml-auto whitespace-nowrap text-[11px] text-muted">計 {total.toLocaleString()}</span>
      </div>
      <div className="mt-1.5 flex items-end gap-px" style={{ height: 46 }}>
        {s.vals.map((v, i) => <div key={i} className="flex-1" style={{ height: `${(v / max) * 44}px`, background: s.color, minWidth: 0 }} />)}
      </div>
    </button>
  );
}
