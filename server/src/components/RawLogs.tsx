'use client';

import { useEffect, useRef, useState } from 'react';
import { Masked, MaskFree } from '@/components/Mask';
import { CAT_LABEL } from '@/lib/logcat';
import { applyLogFilter, readLogFilter, LOG_EVENT, type LogFilter, type LogField } from '@/lib/logfilter';

interface Line { ts: string | null; received_at: string; source: string; message: string; host: string }

const CHIP_LABEL: Record<string, (v: string, ctx: Ctx) => string> = {
  host: (v, c) => `ホスト：${c.hosts[v] ?? v}`,
  cat: (v) => `カテゴリ：${CAT_LABEL[v] ?? v}`,
  vhost: (v) => `サイト：${v}`,
  status: (v) => `ステータス：${v}`,
  source: (v) => `ソース：${v.replace(/^file:/, '')}`,
  rule: (v, c) => `ルール：${c.ruleTitles[v] ?? v}`,
  day: (v) => `日付：${v}`,
  q: (v) => `検索：${v}`,
};
interface Ctx { hosts: Record<string, string>; ruleTitles: Record<string, string> }

export function RawLogs({ hosts, ruleTitles, vhosts, retentionDays }: { hosts: Record<string, string>; ruleTitles: Record<string, string>; vhosts: string[]; retentionDays: number }) {
  const [filter, setFilter] = useState<LogFilter>({});
  const [lines, setLines] = useState<Line[] | null>(null);
  const [loading, setLoading] = useState(false);
  const ctx: Ctx = { hosts, ruleTitles };
  const reqId = useRef(0);

  useEffect(() => {
    setFilter(readLogFilter());
    const on = (e: Event) => setFilter({ ...(e as CustomEvent).detail });
    window.addEventListener(LOG_EVENT, on);
    return () => window.removeEventListener(LOG_EVENT, on);
  }, []);

  useEffect(() => {
    const id = ++reqId.current;
    setLoading(true);
    const u = new URLSearchParams();
    for (const [k, v] of Object.entries(filter)) if (v) u.set(k, v);
    fetch('/api/logs?' + u.toString())
      .then((r) => r.ok ? r.json() : { lines: [] })
      .then((d) => { if (id === reqId.current) setLines(d.lines ?? []); })
      .catch(() => { if (id === reqId.current) setLines([]); })
      .finally(() => { if (id === reqId.current) setLoading(false); });
  }, [filter]);

  const conds = (Object.keys(filter) as LogField[]).filter((k) => k !== 'hours' && filter[k]);
  const hours = filter.hours ?? '24';
  const set = (patch: LogFilter) => applyLogFilter(patch, { scroll: false });

  return (
    <div>
      {conds.length > 0 && (
        <div className="mb-3 flex flex-wrap items-center gap-2">
          <span className="text-xs text-muted">条件：</span>
          {conds.map((k) => (
            <button key={k} type="button" onClick={() => set({ [k]: '' })} className="inline-flex items-center gap-1 rounded-full border border-line px-2 py-0.5 text-xs" style={{ background: 'var(--soft)' }}>
              {(CHIP_LABEL[k] ?? ((v: string) => `${k}：${v}`))(filter[k]!, ctx)}<span className="text-muted">✕</span>
            </button>
          ))}
          <button type="button" onClick={() => applyLogFilter(Object.fromEntries(conds.map((k) => [k, ''])) as LogFilter, { scroll: false })} className="ml-auto text-xs text-accent">すべて解除</button>
        </div>
      )}

      <form className="mb-3 grid grid-cols-2 gap-2 text-sm sm:flex sm:flex-wrap" onSubmit={(e) => e.preventDefault()}>
        <select value={filter.host ?? ''} onChange={(e) => set({ host: e.target.value })} className="input sm:w-auto">
          <option value="">ホスト：すべて</option>
          {Object.entries(hosts).map(([id, name]) => <option key={id} value={id}><Masked kind="host">{name}</Masked></option>)}
        </select>
        <select value={filter.cat ?? ''} onChange={(e) => set({ cat: e.target.value })} className="input sm:w-auto">
          <option value="">カテゴリ：すべて</option>{Object.keys(CAT_LABEL).map((k) => <option key={k} value={k}>{CAT_LABEL[k]}</option>)}
        </select>
        {vhosts.length > 0 && (
          <select value={filter.vhost ?? ''} onChange={(e) => set({ vhost: e.target.value })} className="input sm:w-auto">
            <option value="">サイト：すべて</option>{vhosts.map((v) => <option key={v} value={v}>{v}</option>)}
          </select>
        )}
        <input defaultValue={filter.status ?? ''} key={'st' + (filter.status ?? '')} onKeyDown={(e) => { if (e.key === 'Enter') set({ status: (e.target as HTMLInputElement).value.trim() }); }} onBlur={(e) => set({ status: e.target.value.trim() })} placeholder="ステータス(例 4xx,403)" className="input sm:w-36" />
        {!filter.day && (
          <select value={hours} onChange={(e) => set({ hours: e.target.value })} className="input sm:w-auto">
            {['1', '6', '24', '72', '168', '720'].map((h) => <option key={h} value={h}>{Number(h) < 24 ? `${h}時間` : `${Number(h) / 24}日`}以内</option>)}
          </select>
        )}
        <input defaultValue={filter.q ?? ''} key={'q' + (filter.q ?? '')} onKeyDown={(e) => { if (e.key === 'Enter') set({ q: (e.target as HTMLInputElement).value.trim() }); }} onBlur={(e) => set({ q: e.target.value.trim() })} placeholder="本文を検索（Enter）" className="input sm:w-48" />
      </form>

      {lines === null ? (
        <p className="text-sm text-muted">読み込み中…</p>
      ) : lines.length === 0 ? (
        <p className="text-sm text-muted">この条件に該当する生ログはありません。{filter.day ? `（${filter.day} は生ログの保存期間 ${retentionDays}日 を過ぎている可能性があります）` : ''}</p>
      ) : (
        <div className={`font-mono text-xs ${loading ? 'opacity-50' : ''}`}>
          {lines.map((l, i) => (
            <div key={i} className="flex flex-wrap gap-x-3 border-b border-line py-1 sm:flex-nowrap">
              <span className="whitespace-nowrap text-muted">{l.ts ? new Date(l.ts).toLocaleString('ja-JP') : new Date(l.received_at).toLocaleString('ja-JP')}</span>
              <span className="whitespace-nowrap text-muted"><Masked kind="host">{l.host}</Masked></span>
              <button type="button" onClick={() => set({ source: l.source, cat: '', vhost: '', rule: '' })} className="max-w-[14rem] truncate whitespace-nowrap text-left text-accent">{l.source}</button>
              <span className="w-full min-w-0 break-all sm:w-auto sm:flex-1"><MaskFree>{l.message}</MaskFree></span>
            </div>
          ))}
          {lines.length >= 300 && <p className="mt-2 text-xs text-muted">最新300行を表示（さらに絞り込んでください）。</p>}
        </div>
      )}
    </div>
  );
}
