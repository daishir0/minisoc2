import { Breadcrumbs, CRUMB } from '@/components/Breadcrumbs';
import Link from 'next/link';
import { ExploreTabs } from '@/components/ExploreTabs';
import { Card, ago } from '@/components/ui';
import { q } from '@/lib/db';

// File-integrity (AIDE-style) overview across all hosts: baseline status + recent changes.
export default async function IntegrityPage() {
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
  const changes = await q<{ host: string; host_id: string; created_at: Date; important: boolean; title: string }>(
    `SELECT h.name AS host, e.host_id, e.ts AS created_at, e.important, e.title
     FROM change_events e JOIN hosts h ON h.id=e.host_id
     WHERE e.kind='host_state' AND e.title LIKE '%監視ファイル%' ORDER BY e.ts DESC LIMIT 40`,
  );
  const tracked = hosts.reduce((s, h) => s + Number(h.files), 0);

  return (
    <>
      <Breadcrumbs items={[CRUMB.home, { label: "検知" }]} />
      <ExploreTabs />
      <Card title="ファイル改ざん検知（AIDE相当）">
        <p className="text-sm text-muted">
          各ホストが監視対象のファイルを<b>読み取り専用</b>でハッシュ送信し、ベースラインはサーバー側で保持・<b>自動昇格</b>します。SSH鍵・sudoers・passwd/shadow・実行ファイル・cron・systemd の変化は重要として通知します。全{hosts.length}ホストで{tracked.toLocaleString()}ファイルを監視中。
        </p>
      </Card>
      <Card title="ホスト別のベースライン状態">
        <table className="tbl"><thead><tr><th>ホスト</th><th>種別</th><th>監視ファイル</th><th>ベースライン確定</th><th>最後の変化</th></tr></thead><tbody>
          {hosts.map((h) => (
            <tr key={h.id}>
              <td><Link href={`/hosts/${h.id}`} className="text-accent">{h.name}</Link></td>
              <td className="text-xs text-muted">{h.kind === 'pull' ? 'プル型' : 'エージェント'}</td>
              <td>{Number(h.files) ? Number(h.files).toLocaleString() : <span className="text-muted">未確定</span>}</td>
              <td className="text-xs text-muted">{h.baseline_at ? new Date(h.baseline_at).toISOString().slice(0, 10) : '-'}</td>
              <td className="text-xs">{h.last_change ? <span className={h.important ? 'text-red-600' : 'text-muted'}>{ago(h.last_change)}{h.important ? '（重要）' : ''}</span> : <span className="text-muted">なし</span>}</td>
            </tr>
          ))}
        </tbody></table>
      </Card>
      <Card title="最近の変化">
        {changes.length === 0 ? <p className="text-sm text-muted">ベースライン確定後、変化は検出されていません。</p> : (
          <ul className="divide-y divide-line text-sm">
            {changes.map((e, i) => (
              <li key={i} className="flex flex-wrap items-center gap-2 py-1.5">
                {e.important && <span className="rounded bg-red-600 px-1.5 text-xs text-white">重要</span>}
                <Link href={`/hosts/${e.host_id}`} className="min-w-0 flex-1 truncate">{e.title}</Link>
                <span className="whitespace-nowrap text-xs text-muted">{ago(e.created_at)}</span>
              </li>
            ))}
          </ul>
        )}
      </Card>
    </>
  );
}
