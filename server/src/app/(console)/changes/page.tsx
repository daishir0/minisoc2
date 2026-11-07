import { Breadcrumbs, CRUMB } from '@/components/Breadcrumbs';
import Link from 'next/link';
import { ExploreTabs } from '@/components/ExploreTabs';
import { Masked, MaskFree } from '@/components/Mask';
import { Card } from '@/components/ui';
import { q } from '@/lib/db';
import { KIND_ICON } from '@/lib/timeline';

const KINDS: [string, string][] = [
  ['', 'すべての種類'], ['kev_added', 'KEV入り'], ['vuln_new', '新しい脆弱性'], ['vuln_resolved', '解消'], ['system_new', 'システム追加・基準線'],
  ['host_state', 'ホストの変化'], ['log', 'ログの検知'], ['feed', '脆弱性情報フィード同期'], ['ingest', 'エージェント受信'], ['health', '監視の健全性'], ['ops', '運用の記録'],
];
const KIND_LABEL = Object.fromEntries(KINDS.filter(([k]) => k));
// Per-kind tint: a 4px left bar + a very faint row background (both light/dark). Alarm kinds are more
// saturated; routine high-volume kinds (feed/ingest) are the most muted so the eye lands on real changes.
// Full literal class strings so Tailwind keeps them.
const KIND_STYLE: Record<string, { row: string; dot: string }> = {
  kev_added: { row: 'border-red-400 bg-red-50 dark:bg-red-950/30', dot: 'bg-red-400' },
  vuln_new: { row: 'border-orange-400 bg-orange-50 dark:bg-orange-950/30', dot: 'bg-orange-400' },
  vuln_resolved: { row: 'border-green-400 bg-green-50 dark:bg-green-950/30', dot: 'bg-green-400' },
  system_new: { row: 'border-blue-400 bg-blue-50 dark:bg-blue-950/30', dot: 'bg-blue-400' },
  host_state: { row: 'border-violet-400 bg-violet-50 dark:bg-violet-950/30', dot: 'bg-violet-400' },
  log: { row: 'border-teal-400 bg-teal-50 dark:bg-teal-950/30', dot: 'bg-teal-400' },
  health: { row: 'border-yellow-400 bg-yellow-50 dark:bg-yellow-950/30', dot: 'bg-yellow-400' },
  ops: { row: 'border-zinc-300 bg-zinc-50 dark:bg-zinc-900/40', dot: 'bg-zinc-400' },
  feed: { row: 'border-slate-300 bg-slate-50/60 dark:bg-slate-900/30', dot: 'bg-slate-400' },
  ingest: { row: 'border-slate-200 dark:border-slate-700', dot: 'bg-slate-300' },
};
const DEFAULT_STYLE = { row: 'border-line', dot: 'bg-slate-400' };
const PAGE = 500;

// Full timestamp down to the second (process-local time), newest first.
const fmtTs = (d: Date) => new Date(d).toLocaleString('ja-JP', { year: 'numeric', month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false });

export default async function ChangesPage({ searchParams }: { searchParams: Promise<Record<string, string | undefined>> }) {
  const sp = await searchParams;
  // Full activity log: every event in time order, NEWEST FIRST, one line per event with a to-the-second
  // timestamp and its detail. "重要のみ" narrows to the important lines (what the home page surfaces);
  // the home page itself always calls timeline({importantOnly:true}) so it stays quiet.
  const importantOnly = sp.imp === '1';
  const days = [1, 7, 30, 90, 180].includes(Number(sp.days)) ? Number(sp.days) : 30;
  const hostId = sp.host && /^[0-9a-f-]{36}$/.test(sp.host) ? sp.host : undefined;
  const kind = KINDS.some(([k]) => k && k === sp.kind) ? sp.kind : undefined;
  const hosts = await q<{ id: string; name: string }>('SELECT id, name FROM hosts ORDER BY name');

  const where = [`e.ts > now() - ($1 || ' days')::interval`];
  const params: unknown[] = [String(days)];
  if (importantOnly) where.push('e.important');
  if (hostId) { params.push(hostId); where.push(`e.host_id=$${params.length}`); }
  if (kind) { params.push(kind); where.push(`e.kind=$${params.length}`); }
  const rows = await q<{ ts: Date; kind: string; important: boolean; count: number; title: string; detail: string | null; host: string | null; host_id: string | null }>(
    `SELECT e.ts, e.kind, e.important, e.count, e.title, e.detail, h.name AS host, e.host_id
     FROM change_events e LEFT JOIN hosts h ON h.id=e.host_id
     WHERE ${where.join(' AND ')}
     ORDER BY e.ts DESC
     LIMIT ${PAGE}`,
    params,
  );

  return (
    <>
      <Breadcrumbs items={[CRUMB.home, { label: '検知' }]} />
      <ExploreTabs />
      <Card title="変化・活動の履歴（新しい順）">
        <form className="mb-3 grid grid-cols-2 gap-2 text-sm sm:flex sm:flex-wrap" action="/changes">
          <select name="days" defaultValue={String(days)} className="input sm:w-auto">{[1, 7, 30, 90, 180].map((d) => <option key={d} value={d}>{d}日</option>)}</select>
          <select name="host" defaultValue={hostId ?? ''} className="input sm:w-auto"><option value="">全ホスト</option>{hosts.map((h) => <option key={h.id} value={h.id}><Masked kind="host">{h.name}</Masked></option>)}</select>
          <select name="kind" defaultValue={kind ?? ''} className="input sm:w-auto">{KINDS.map(([k, l]) => <option key={k} value={k}>{l}</option>)}</select>
          <label className="flex items-center gap-1"><input type="checkbox" name="imp" value="1" defaultChecked={importantOnly} /> 重要な変化だけ</label>
          <button className="btn">表示</button>
        </form>
        <p className="mb-3 text-xs text-muted">
          {importantOnly ? '重要な変化だけを、' : 'すべての活動（脆弱性情報フィードの同期・エージェントからのデータ受信を含む）を、'}
          新しい順・1件ずつ（秒まで）で表示しています。{importantOnly && <Link className="ml-1 text-accent" href={`/changes?days=${days}`}>すべて表示</Link>}
          {rows.length >= PAGE && <span className="ml-1">（最新{PAGE}件。期間や種別で絞り込めます）</span>}
        </p>
        <div className="mb-3 flex flex-wrap gap-x-3 gap-y-1 text-[11px] text-muted">
          {KINDS.filter(([k]) => k).map(([k, l]) => (
            <span key={k} className="inline-flex items-center gap-1"><span className={`inline-block h-2.5 w-2.5 rounded-sm ${(KIND_STYLE[k] ?? DEFAULT_STYLE).dot}`} />{l}</span>
          ))}
        </div>
        {rows.length === 0 ? (
          <p className="text-sm text-muted">この条件に該当する記録はありません。</p>
        ) : (
          <ul className="space-y-1">
            {rows.map((e, i) => (
              <li key={i} className={`flex flex-col gap-0.5 rounded-r border-l-4 ${(KIND_STYLE[e.kind] ?? DEFAULT_STYLE).row} px-2 py-2 text-sm sm:flex-row sm:items-start sm:gap-3`}>
                <span className="shrink-0 whitespace-nowrap font-mono text-xs text-muted" title={new Date(e.ts).toISOString()}>{fmtTs(e.ts)}</span>
                <span className="min-w-0 flex-1">
                  <span className="flex flex-wrap items-center gap-x-2 gap-y-1">
                    <span aria-hidden="true">{KIND_ICON[e.kind] ?? '・'}</span>
                    <span className="rounded bg-bg px-1.5 py-0.5 text-[10px] text-muted">{KIND_LABEL[e.kind] ?? e.kind}</span>
                    {e.important && <span className="rounded bg-red-600 px-1.5 py-0.5 text-[10px] text-white">重要</span>}
                    {e.count > 1 && <span className="rounded bg-bg px-1.5 py-0.5 text-[10px] text-muted">×{e.count}</span>}
                    {e.host && <Link href={`/hosts/${e.host_id}`} className="text-xs text-accent"><Masked kind="host">{e.host}</Masked></Link>}
                    <span className={`break-words ${e.important ? 'font-medium' : ''}`}><MaskFree>{e.title}</MaskFree></span>
                  </span>
                  {e.detail && <span className="mt-0.5 block whitespace-pre-wrap break-words text-xs text-muted"><MaskFree>{e.detail.slice(0, 1000)}</MaskFree></span>}
                </span>
              </li>
            ))}
          </ul>
        )}
      </Card>
    </>
  );
}
