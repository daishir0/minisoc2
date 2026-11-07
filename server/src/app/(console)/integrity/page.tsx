import { Breadcrumbs, CRUMB } from '@/components/Breadcrumbs';
import Link from 'next/link';
import { ExploreTabs } from '@/components/ExploreTabs';
import { Masked, MaskFree } from '@/components/Mask';
import { Card, ago } from '@/components/ui';
import { q } from '@/lib/db';

// File-integrity overview. The server holds a continuously-promoted baseline per host; once a day (at the
// configured hour) that baseline is snapshotted and diffed against the previous day's snapshot, so this
// page shows "what changed in the last day" at a fixed cadence (the diff is at most one day). The home
// page surfaces only the important count; the full day-by-day history lives here.
const KIND_LABEL: Record<string, string> = { added: '追加', changed: '変更', removed: '削除' };
const SEV_LABEL: Record<string, string> = { critical: '重大', high: '高', medium: '中', low: '低' };
const SEV_CLS: Record<string, string> = {
  critical: 'bg-red-600 text-white', high: 'bg-orange-100 text-orange-700 dark:bg-orange-950 dark:text-orange-200',
  medium: 'bg-yellow-100 text-yellow-800 dark:bg-yellow-950 dark:text-yellow-200', low: 'bg-bg text-muted',
};
const SEV_RANK: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3 };

export default async function IntegrityPage({ searchParams }: { searchParams: Promise<{ day?: string }> }) {
  const sp = await searchParams;
  const hosts = await q<{ id: string; name: string; kind: string; baseline_at: Date | null; files: string; last_change: Date | null; important: boolean | null }>(
    `SELECT h.id, h.name, h.kind, h.file_baseline_at AS baseline_at,
       (SELECT count(*) FROM host_file_baseline b WHERE b.host_id=h.id) AS files,
       ce.last_change, ce.important
     FROM hosts h
     LEFT JOIN LATERAL (
       SELECT ts AS last_change, important FROM change_events e
       WHERE e.host_id=h.id AND e.kind='host_state' AND e.title LIKE '%監視ファイル%'
       ORDER BY ts DESC LIMIT 1
     ) ce ON true
     WHERE NOT h.disabled ORDER BY h.name`,
  );
  const tracked = hosts.reduce((s, h) => s + Number(h.files), 0);

  // Days that have a captured snapshot diff (newest first); default to the latest.
  const days = (await q<{ day: string }>("SELECT DISTINCT to_char(day, 'YYYY-MM-DD') AS day FROM host_file_day ORDER BY day DESC LIMIT 60")).map((r) => r.day);
  const day = sp.day && days.includes(sp.day) ? sp.day : days[0];
  const diffs = day
    ? await q<{ host: string; host_id: string; path: string; kind: string; sev: string }>(
        `SELECT h.name AS host, d.host_id, d.path, d.kind, d.sev
         FROM host_file_day d JOIN hosts h ON h.id=d.host_id
         WHERE d.day=$1
         ORDER BY CASE d.sev WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 ELSE 3 END, h.name, d.path`,
        [day],
      )
    : [];
  const important = diffs.filter((d) => d.sev === 'critical' || d.sev === 'high').length;

  return (
    <>
      <Breadcrumbs items={[CRUMB.home, { label: '検知' }]} />
      <ExploreTabs />
      <Card title="ファイル改ざん検知（AIDE相当）">
        <p className="text-sm text-muted">
          各ホストが監視対象のファイルを<b>読み取り専用</b>でハッシュ送信します。サーバーは<b>毎日同じ時刻（設定の「日次照合時刻」）に状態を1回取得</b>し、<b>前日との差分</b>を表示します（＝ここに出る差分は最大で1日分）。SSH鍵・sudoers・passwd/shadow・実行ファイル・cron・systemd の変化は重要として扱います。全{hosts.length}ホストで{tracked.toLocaleString()}ファイルを監視中。
        </p>
        <p className="mt-1 text-xs text-muted">※リアルタイムの改ざんアラート（重要パスの即時通知）は従来どおり「アラート」で届きます。この画面は日次の俯瞰用です。</p>
      </Card>

      <Card title="日次の変化（前日比）">
        {days.length === 0 ? (
          <p className="text-sm text-muted">まだ日次スナップショットがありません（初回取得は次回の日次処理時刻から。取得2回目以降に差分が出ます）。</p>
        ) : (
          <>
            <form className="mb-3 flex flex-wrap items-center gap-2 text-sm" action="/integrity">
              <span className="text-muted">日付</span>
              <select name="day" defaultValue={day} className="input sm:w-auto">{days.map((d) => <option key={d} value={d}>{d}</option>)}</select>
              <button className="btn">表示</button>
              <span className="ml-auto text-xs text-muted">{day}：変化 {diffs.length}件{important ? `（重要 ${important}）` : ''}</span>
            </form>
            {diffs.length === 0 ? (
              <p className="text-sm text-green-600">✅ {day} は前日からの変化はありませんでした。</p>
            ) : (
              <ul className="divide-y divide-line text-sm">
                {diffs.map((d, i) => (
                  <li key={i} className="flex flex-wrap items-center gap-2 py-1.5">
                    <span className={`rounded px-1.5 py-0.5 text-[10px] ${SEV_CLS[d.sev] ?? 'bg-bg text-muted'}`}>{SEV_LABEL[d.sev] ?? d.sev}</span>
                    <span className="rounded bg-bg px-1.5 py-0.5 text-[10px] text-muted">{KIND_LABEL[d.kind] ?? d.kind}</span>
                    <Link href={`/hosts/${d.host_id}`} className="text-accent"><Masked kind="host">{d.host}</Masked></Link>
                    <span className="min-w-0 flex-1 break-all font-mono text-xs"><MaskFree>{d.path}</MaskFree></span>
                  </li>
                ))}
              </ul>
            )}
          </>
        )}
      </Card>

      <Card title="ホスト別のベースライン状態">
        <table className="tbl"><thead><tr><th>ホスト</th><th>種別</th><th>監視ファイル</th><th>ベースライン確定</th><th>最後の変化</th></tr></thead><tbody>
          {hosts.map((h) => (
            <tr key={h.id}>
              <td><Link href={`/hosts/${h.id}`} className="text-accent"><Masked kind="host">{h.name}</Masked></Link></td>
              <td className="text-xs text-muted">{h.kind === 'pull' ? 'プル型' : 'エージェント'}</td>
              <td>{Number(h.files) ? Number(h.files).toLocaleString() : <span className="text-muted">未確定</span>}</td>
              <td className="text-xs text-muted">{h.baseline_at ? new Date(h.baseline_at).toISOString().slice(0, 10) : '-'}</td>
              <td className="text-xs">{h.last_change ? <span className={h.important ? 'text-red-600' : 'text-muted'}>{ago(h.last_change)}{h.important ? '（重要）' : ''}</span> : <span className="text-muted">なし</span>}</td>
            </tr>
          ))}
        </tbody></table>
      </Card>
    </>
  );
}
