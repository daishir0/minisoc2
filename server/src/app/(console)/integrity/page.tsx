import { Breadcrumbs, CRUMB } from '@/components/Breadcrumbs';
import Link from 'next/link';
import { ExploreTabs } from '@/components/ExploreTabs';
import { Masked, MaskFree } from '@/components/Mask';
import { Card, ago } from '@/components/ui';
import { q } from '@/lib/db';
import { pathSeverity } from '@/lib/fileintegrity';

// File-integrity overview. The server holds a continuously-promoted baseline per host; once a day (at the
// configured hour) that baseline is snapshotted (host_file_snap) and the day-over-day diff is persisted to
// host_file_day. This page shows (1) the LIVE diff since that basepoint — which files changed and how,
// straight from the received hashes, usable immediately — and (2) the persisted day-by-day history.
const KIND_LABEL: Record<string, string> = { added: '追加', changed: '変更', removed: '削除' };
const SEV_LABEL: Record<string, string> = { critical: '重大', high: '高', medium: '中', low: '低' };
const SEV_CLS: Record<string, string> = {
  critical: 'bg-red-600 text-white', high: 'bg-orange-100 text-orange-700 dark:bg-orange-950 dark:text-orange-200',
  medium: 'bg-yellow-100 text-yellow-800 dark:bg-yellow-950 dark:text-yellow-200', low: 'bg-bg text-muted',
};
const KIND_CLS: Record<string, string> = {
  added: 'bg-blue-100 text-blue-700 dark:bg-blue-950 dark:text-blue-200',
  changed: 'bg-amber-100 text-amber-800 dark:bg-amber-950 dark:text-amber-200',
  removed: 'bg-slate-200 text-slate-600 dark:bg-slate-800 dark:text-slate-300',
};
const SEV_RANK: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3 };
const sh = (x?: string | null) => (x ? x.slice(0, 8) : '');
const PER_HOST = 100;

// How the change reads, from the received hashes.
function changeText(kind: string, oldSha?: string | null, newSha?: string | null): string {
  if (kind === 'added') return `新規（${sh(newSha) || '—'}）`;
  if (kind === 'removed') return '削除された';
  return `内容が変化 ${sh(oldSha) || '—'} → ${sh(newSha) || '—'}`;
}

type Row = { host: string; host_id: string; path: string; kind: string; sev: string; old_sha: string | null; new_sha: string | null };

function HostDiffList({ rows }: { rows: Row[] }) {
  const byHost = new Map<string, Row[]>();
  for (const r of rows) byHost.set(r.host, [...(byHost.get(r.host) ?? []), r]);
  return (
    <div className="space-y-4">
      {[...byHost.entries()].map(([host, frs]) => {
        const imp = frs.filter((f) => f.sev === 'critical' || f.sev === 'high').length;
        return (
          <div key={host}>
            <div className="mb-1 flex flex-wrap items-center gap-2 text-sm">
              <Link href={`/hosts/${frs[0].host_id}`} className="font-medium text-accent"><Masked kind="host">{host}</Masked></Link>
              <span className="text-xs text-muted">変化 {frs.length}件{imp ? `・重要 ${imp}` : ''}</span>
            </div>
            <ul className="divide-y divide-line text-sm">
              {frs.slice(0, PER_HOST).map((d, i) => (
                <li key={i} className="flex flex-wrap items-center gap-2 py-1.5">
                  <span className={`rounded px-1.5 py-0.5 text-[10px] ${SEV_CLS[d.sev] ?? 'bg-bg text-muted'}`}>{SEV_LABEL[d.sev] ?? d.sev}</span>
                  <span className={`rounded px-1.5 py-0.5 text-[10px] ${KIND_CLS[d.kind] ?? 'bg-bg text-muted'}`}>{KIND_LABEL[d.kind] ?? d.kind}</span>
                  <span className="min-w-0 flex-1 break-all font-mono text-xs"><MaskFree>{d.path}</MaskFree></span>
                  <span className="whitespace-nowrap font-mono text-[11px] text-muted">{changeText(d.kind, d.old_sha, d.new_sha)}</span>
                </li>
              ))}
            </ul>
            {frs.length > PER_HOST && <p className="mt-1 text-xs text-muted">…ほか {frs.length - PER_HOST} 件</p>}
          </div>
        );
      })}
    </div>
  );
}

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
  const basepoint = (await q<{ d: string }>("SELECT value->>'date' AS d FROM settings WHERE key='last_file_snapshot'"))[0]?.d ?? null;

  // LIVE diff: current baseline vs the daily basepoint snapshot — which files changed since the basepoint
  // and how (from the received hashes). Works as soon as a basepoint exists (no need to wait for 2 AM).
  const liveRaw = await q<{ host: string; host_id: string; path: string; old_sha: string | null; new_sha: string | null; kind: string }>(
    `SELECT h.name AS host, COALESCE(b.host_id, s.host_id) AS host_id, COALESCE(b.path, s.path) AS path,
            s.sha AS old_sha, b.sha AS new_sha,
            CASE WHEN b.path IS NULL THEN 'removed' WHEN s.path IS NULL THEN 'added' ELSE 'changed' END AS kind
     FROM host_file_baseline b
     FULL OUTER JOIN host_file_snap s ON s.host_id=b.host_id AND s.path=b.path
     JOIN hosts h ON h.id = COALESCE(b.host_id, s.host_id)
     WHERE b.sha IS DISTINCT FROM s.sha AND NOT h.disabled
     LIMIT 2000`,
  );
  const live: Row[] = liveRaw.map((r) => ({ ...r, sev: pathSeverity(r.path) }))
    .sort((a, b) => (SEV_RANK[a.sev] - SEV_RANK[b.sev]) || a.host.localeCompare(b.host) || a.path.localeCompare(b.path));

  // Persisted day-by-day history (host_file_day).
  const days = (await q<{ day: string }>("SELECT DISTINCT to_char(day, 'YYYY-MM-DD') AS day FROM host_file_day ORDER BY day DESC LIMIT 60")).map((r) => r.day);
  const day = sp.day && days.includes(sp.day) ? sp.day : days[0];
  const hist: Row[] = day
    ? (await q<Row>(
        `SELECT h.name AS host, d.host_id, d.path, d.kind, d.sev, d.old_sha, d.new_sha
         FROM host_file_day d JOIN hosts h ON h.id=d.host_id WHERE d.day=$1
         ORDER BY CASE d.sev WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 ELSE 3 END, h.name, d.path`, [day]))
    : [];

  return (
    <>
      <Breadcrumbs items={[CRUMB.home, { label: '検知' }]} />
      <ExploreTabs />
      <Card title="ファイル改ざん検知（AIDE相当）">
        <p className="text-sm text-muted">
          各ホストが監視対象のファイルを<b>読み取り専用</b>でハッシュ送信します。サーバーは<b>毎日同じ時刻（設定の「日次照合時刻」）に基点を1回取得</b>し、以降の変化を<b>追加 / 変更（ハッシュ前後）/ 削除</b>で示します。SSH鍵・sudoers・passwd/shadow・実行ファイル・cron・systemd の変化は重要として扱います。全{hosts.length}ホストで{tracked.toLocaleString()}ファイルを監視中。
        </p>
        <p className="mt-1 text-xs text-muted">※重要パスの<b>リアルタイム</b>改ざんは従来どおり「アラート」で即通知します。</p>
      </Card>

      <Card title={`現在の変化（前回の基点${basepoint ? ` ${basepoint}` : ''} 以降・ホスト別）`}>
        {live.length === 0 ? (
          <p className="text-sm text-green-600">✅ すべてのホストで、基点から現在までのファイル変化はありません。</p>
        ) : (
          <>
            <p className="mb-3 text-xs text-muted">受信した最新ハッシュと基点を突き合わせた<b>現時点の差分</b>です（最大 {live.length} 件表示）。</p>
            <HostDiffList rows={live} />
          </>
        )}
      </Card>

      <Card title="日次の変化（履歴）">
        {days.length === 0 ? (
          <p className="text-sm text-muted">まだ日次スナップショットの履歴がありません（初回の確定差分は次回の日次処理時刻から記録されます）。</p>
        ) : (
          <>
            <form className="mb-3 flex flex-wrap items-center gap-2 text-sm" action="/integrity">
              <span className="text-muted">日付</span>
              <select name="day" defaultValue={day} className="input sm:w-auto">{days.map((d) => <option key={d} value={d}>{d}</option>)}</select>
              <button className="btn">表示</button>
              <span className="ml-auto text-xs text-muted">{day}：変化 {hist.length}件</span>
            </form>
            {hist.length === 0 ? <p className="text-sm text-green-600">✅ {day} は前日からの変化はありませんでした。</p> : <HostDiffList rows={hist} />}
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
