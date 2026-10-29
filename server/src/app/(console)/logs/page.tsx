import Link from 'next/link';
import { ExploreTabs } from '@/components/ExploreTabs';
import { Card, ago } from '@/components/ui';
import { q } from '@/lib/db';
import { rawIngestPaused } from '@/lib/logs';
import { RULES } from '@/lib/rules';
import { getPolicy } from '@/lib/settings';

const RULE_TITLE = Object.fromEntries(RULES.map((r) => [r.id, r.title]));

export default async function LogsPage({ searchParams }: { searchParams: Promise<Record<string, string | undefined>> }) {
  const sp = await searchParams;
  const policy = await getPolicy();
  const paused = await rawIngestPaused();
  const hosts = await q<{ id: string; name: string }>('SELECT id, name FROM hosts ORDER BY name');
  const hostOk = sp.host && /^[0-9a-f-]{36}$/.test(sp.host) ? sp.host : undefined;
  const hostCond = hostOk ? 'AND host_id=$1' : '';
  const hp = hostOk ? [hostOk] : [];

  const days = await q<{ day: string; lines: string }>(
    `SELECT to_char(day, 'YYYY-MM-DD') AS day, sum(lines) AS lines FROM log_daily WHERE day > current_date - 30 ${hostCond} GROUP BY day ORDER BY day`, hp,
  );
  const max = Math.max(1, ...days.map((d) => Number(d.lines)));
  const rules = await q<{ rule_id: string; today: string; week: string }>(
    `SELECT rule_id, sum(hits) FILTER (WHERE day = current_date) AS today, sum(hits) AS week
     FROM log_rule_daily WHERE day > current_date - 7 ${hostCond} GROUP BY rule_id ORDER BY 3 DESC`, hp,
  );
  const sources = await q<{ source: string; lines: string }>(
    `SELECT source, sum(lines) AS lines FROM log_daily WHERE day > current_date - 7 ${hostCond} GROUP BY source ORDER BY 2 DESC LIMIT 50`, hp,
  );
  // Sigma rule titles (for rows whose rule_id is "sigma:...") and feed status.
  const sigmaTitles = Object.fromEntries((await q<{ id: string; title: string }>('SELECT id, title FROM sigma_rules')).map((r) => [r.id, `Sigma: ${r.title}`]));
  const title = (id: string) => RULE_TITLE[id] ?? sigmaTitles[id] ?? id;
  const sigmaFeed = (await q<{ item_count: number | null; last_success: Date | null }>("SELECT item_count, last_success FROM feed_status WHERE name='sigma'"))[0];

  const where: string[] = [];
  const params: unknown[] = [];
  if (hostOk) { params.push(hostOk); where.push(`l.host_id=$${params.length}`); }
  if (sp.source) { params.push(sp.source); where.push(`l.source=$${params.length}`); }
  if (sp.q) { params.push(`%${sp.q}%`); where.push(`l.message ILIKE $${params.length}`); }
  const hours = Math.min(24 * 365, Math.max(1, Number(sp.hours ?? 24) || 24));
  params.push(String(hours));
  where.push(`l.received_at > now() - ($${params.length} || ' hours')::interval`);
  const lines = await q<{ received_at: Date; ts: Date | null; source: string; message: string; host: string }>(
    `SELECT l.received_at, l.ts, l.source, l.message, h.name AS host FROM raw_logs l JOIN hosts h ON h.id=l.host_id
     WHERE ${where.join(' AND ')} ORDER BY l.received_at DESC, l.ts DESC NULLS LAST LIMIT 300`,
    params,
  );

  return (
    <>
      <ExploreTabs />
      {paused && (
        <div className="rounded-md border border-orange-400 bg-orange-50 px-4 py-3 text-sm text-orange-900 dark:bg-orange-950 dark:text-orange-100">
          ディスク使用率が上限（{policy.diskGuardPercent}%）を超えたため、生ログの保存を停止しています。ルール判定と集計は続けています。
        </div>
      )}
      <form className="grid grid-cols-2 gap-2 text-sm sm:flex sm:flex-wrap" action="/logs">
        <select name="host" defaultValue={hostOk ?? ''} className="input sm:w-auto">
          <option value="">全ホスト</option>
          {hosts.map((h) => <option key={h.id} value={h.id}>{h.name}</option>)}
        </select>
        <select name="source" defaultValue={sp.source ?? ''} className="input sm:w-auto sm:max-w-xs">
          <option value="">全ソース</option>
          {sources.map((s) => <option key={s.source} value={s.source}>{s.source}</option>)}
        </select>
        <select name="hours" defaultValue={String(hours)} className="input sm:w-auto">
          {[1, 6, 24, 72, 168, 720].map((h) => <option key={h} value={h}>{h < 24 ? `${h}時間` : `${h / 24}日`}以内</option>)}
        </select>
        <input name="q" defaultValue={sp.q ?? ''} placeholder="本文を検索" className="input sm:w-56" />
        <button className="btn">検索</button>
      </form>
      <div className="grid gap-6 lg:grid-cols-2">
        <Card title="日別のログ量（30日・集計は永続保存）">
          {days.length === 0 ? <p className="text-sm text-muted">まだログが届いていません。</p> : (
            <div className="flex items-end gap-1" style={{ height: 160 }}>
              {days.map((d) => (
                <div key={d.day} style={{ display: 'flex', flexDirection: 'column', justifyContent: 'flex-end', alignItems: 'center', height: '100%', flex: 1, maxWidth: 28 }} title={`${d.day}: ${Number(d.lines).toLocaleString()}行`}>
                  <div className="w-full rounded-t" style={{ height: `${Math.max(2, Math.round((Number(d.lines) / max) * 160))}px`, background: 'var(--accent)' }} />
                </div>
              ))}
            </div>
          )}
          {days.length > 0 && <div className="mt-1 flex justify-between text-xs text-muted"><span>{days[0].day}</span><span>{days[days.length - 1].day}</span></div>}
        </Card>
        <Card title="検知ルールに一致したログの件数（7日・アラート数ではありません）">
          <p className="mb-2 text-xs text-muted">
            自作の高シグナルルールに加え、Sigma（SigmaHQ）ルール {sigmaFeed?.item_count ?? 0} 件を適用中
            {sigmaFeed?.last_success ? `（最終同期 ${ago(sigmaFeed.last_success)}）` : '（同期待ち）'}。
          </p>
          {rules.length === 0 ? <p className="text-sm text-muted">一致はありません。</p> : (
            <table className="tbl"><thead><tr><th>ルール</th><th>今日</th><th>7日</th></tr></thead><tbody>
              {rules.map((r) => <tr key={r.rule_id}><td>{title(r.rule_id)}</td><td>{r.today ?? 0}</td><td>{r.week}</td></tr>)}
            </tbody></table>
          )}
        </Card>
      </div>
      <Card title={`ログ（新しい順・最大300行／生ログの保存期間 ${policy.logRetentionDays}日）`}>
        {lines.length === 0 ? <p className="text-sm text-muted">該当するログはありません。</p> : (
          <div className="font-mono text-xs">
            {lines.map((l, i) => (
              <div key={i} className="flex flex-wrap gap-x-3 border-b border-line py-1 sm:flex-nowrap">
                <span className="whitespace-nowrap text-muted" title={new Date(l.received_at).toLocaleString('ja-JP')}>{l.ts ? new Date(l.ts).toLocaleString('ja-JP') : ago(l.received_at)}</span>
                <span className="whitespace-nowrap text-muted">{l.host}</span>
                <Link href={`/logs?source=${encodeURIComponent(l.source)}${hostOk ? `&host=${hostOk}` : ''}`} className="max-w-[14rem] truncate whitespace-nowrap text-accent">{l.source}</Link>
                <span className="w-full min-w-0 break-all sm:w-auto sm:flex-1">{l.message}</span>
              </div>
            ))}
          </div>
        )}
      </Card>
    </>
  );
}
