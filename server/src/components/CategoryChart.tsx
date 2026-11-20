'use client';

import { useEffect, useState } from 'react';

export interface CatPoint { day: string; web: number; auth: number; audit: number; sys: number }
type Key = 'auth' | 'web' | 'sys' | 'audit';
const CATS: [Key, string, string][] = [
  ['auth', '認証', '#2563eb'], ['web', 'Web', '#0e7c86'], ['sys', 'システム', '#8b5cf6'], ['audit', '監査', '#d97706'],
];
const LS_KEY = 'logs.catHidden';

// Category-stacked daily log volume. Legend entries are checkboxes (uncheck to drop a series from the
// stack); the choice persists in localStorage so the chart looks the same on the next visit. Clicking a
// bar segment or a legend name opens that category's raw logs.
export function CategoryChart({ points }: { points: CatPoint[] }) {
  const [hidden, setHidden] = useState<Set<Key>>(new Set());
  const [ready, setReady] = useState(false);
  useEffect(() => {
    try { const r = localStorage.getItem(LS_KEY); if (r) setHidden(new Set(JSON.parse(r))); } catch { /* ignore */ }
    setReady(true);
  }, []);
  const toggle = (k: Key) => setHidden((prev) => {
    const n = new Set(prev); if (n.has(k)) n.delete(k); else n.add(k);
    try { localStorage.setItem(LS_KEY, JSON.stringify([...n])); } catch { /* ignore */ }
    return n;
  });
  const drill = (k: Key) => { try { location.assign('/logs?cat=' + k + '#raw'); } catch { /* ignore */ } };
  const vis = CATS.filter((c) => !hidden.has(c[0]));
  const tot = (p: CatPoint) => vis.reduce((a, c) => a + (p[c[0]] || 0), 0);
  const max = Math.max(1, ...points.map(tot));
  return (
    <div>
      {points.length < 2 ? <p className="text-sm text-muted">まだ集計がたまっていません。</p> : (
        <div className="flex items-end gap-1" style={{ height: 150 }} aria-hidden={!ready}>
          {points.map((p, i) => (
            <div key={i} title={`${p.day}: ${tot(p).toLocaleString()}行`} className="flex flex-1 flex-col justify-end" style={{ maxWidth: 26, height: '100%' }}>
              {vis.map((c) => { const h = ((p[c[0]] || 0) / max) * 140; return h > 0.3 ? <div key={c[0]} onClick={() => drill(c[0])} title={`${c[1]} ${(p[c[0]] || 0).toLocaleString()}`} style={{ height: `${h}px`, background: c[2], cursor: 'pointer' }} /> : null; })}
            </div>
          ))}
        </div>
      )}
      <div className="mt-2 flex flex-wrap items-center gap-x-4 gap-y-1.5 text-xs">
        {CATS.map((c) => (
          <span key={c[0]} className="inline-flex items-center gap-1.5">
            <input type="checkbox" checked={!hidden.has(c[0])} onChange={() => toggle(c[0])} aria-label={`${c[1]}を表示`} className="accent-[var(--accent)]" />
            <button type="button" onClick={() => drill(c[0])} className="inline-flex items-center gap-1 text-muted hover:text-fg">
              <span className="inline-block h-3 w-3 rounded-sm" style={{ background: c[2] }} />{c[1]}
            </button>
          </span>
        ))}
        <span className="ml-auto text-muted">チェックで表示切替／名前・棒クリックで生ログへ</span>
      </div>
    </div>
  );
}
