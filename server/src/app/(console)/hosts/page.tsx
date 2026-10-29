import Link from 'next/link';
import { AssetTabs } from '@/components/AssetTabs';
import { Card, ago } from '@/components/ui';
import { q } from '@/lib/db';

export default async function HostsPage() {
  const hosts = await q<{
    id: string; name: string; hostname: string; os_name: string; os_version: string; agent_version: string;
    last_seen_at: Date | null; stale_alerted: boolean; disabled: boolean; c: string; h: string; k: string; total: string; errs: number | null;
  }>(
    `SELECT h.id, h.name, h.hostname, h.os_name, h.os_version, h.agent_version, h.last_seen_at, h.stale_alerted, h.disabled,
       count(f.id) FILTER (WHERE NOT f.kev AND f.severity='critical') AS c, count(f.id) FILTER (WHERE f.severity='high') AS h,
       count(f.id) FILTER (WHERE f.kev) AS k, count(f.id) AS total,
       (SELECT jsonb_array_length(errors) FROM reports r WHERE r.host_id=h.id ORDER BY received_at DESC LIMIT 1) AS errs
     FROM hosts h LEFT JOIN findings f ON f.host_id=h.id AND f.status='open'
     GROUP BY h.id ORDER BY h.name`,
  );
  return (
    <>
      <AssetTabs />
      <div className="flex flex-wrap gap-2 text-sm">
        <Link className="btn-ghost" href="/enroll">エージェント型ホストを追加</Link>
        <Link className="btn-ghost" href="/hosts/pull/new">プル型ホストを追加（SSH）</Link>
      </div>
    <Card title={`ホスト（${hosts.length}台）`}>
      {hosts.length === 0 ? <p className="text-sm text-muted">ホストはまだありません。<Link className="text-accent" href="/enroll">最初のホストを追加</Link>してください。</p> : (
        <>
        {/* phones: one card per host */}
        <ul className="divide-y divide-line md:hidden">
          {hosts.map((h) => (
            <li key={h.id} className={`py-3 ${h.disabled ? 'opacity-50' : ''}`}>
              <span className={`mr-1.5 inline-block h-2 w-2 rounded-full ${h.disabled ? 'bg-slate-400' : h.stale_alerted ? 'bg-orange-500' : 'bg-green-500'}`} />
              <Link className="break-all font-medium text-accent" href={`/hosts/${h.id}`}>{h.name}</Link>
              <div className="mt-0.5 text-xs text-muted">{h.os_name} {h.os_version} · エージェント {h.agent_version}{h.errs ? <span className="text-orange-500"> · 収集エラー{h.errs}</span> : null}</div>
              <div className={`text-xs ${h.stale_alerted ? 'text-orange-500' : 'text-muted'}`}>最終報告 {h.disabled ? '無効' : ago(h.last_seen_at)}</div>
              <div className="mt-1.5 flex flex-wrap gap-3 text-sm"><span className={Number(h.k) ? 'font-semibold text-red-600' : ''}>KEV {h.k}</span><span>緊急 {h.c}</span><Link className="text-muted underline" href={`/findings?host=${h.id}&all=1`}>その他 {Number(h.total) - Number(h.k) - Number(h.c)}</Link></div>
            </li>
          ))}
        </ul>
        <div className="hidden overflow-x-auto md:block">
          <table className="tbl">
            <thead><tr><th>名前</th><th>OS</th><th>エージェント</th><th>最終報告</th><th>KEV</th><th>緊急</th><th>その他</th></tr></thead>
            <tbody>
              {hosts.map((h) => (
                <tr key={h.id} className={h.disabled ? 'opacity-50' : ''}>
                  <td><span className={`mr-1.5 inline-block h-2 w-2 rounded-full ${h.disabled ? 'bg-slate-400' : h.stale_alerted ? 'bg-orange-500' : 'bg-green-500'}`} title={h.disabled ? '無効' : h.stale_alerted ? '報告停止' : '報告中'} /><Link className="text-accent" href={`/hosts/${h.id}`}>{h.name}</Link>{h.name !== h.hostname && <div className="text-xs text-muted">{h.hostname}</div>}</td>
                  <td>{h.os_name} {h.os_version}</td>
                  <td className="font-mono text-xs">{h.agent_version}{h.errs ? <span className="ml-1 text-orange-500" title="直近の報告に収集エラーあり">!{h.errs}</span> : null}</td>
                  <td className={h.stale_alerted ? 'text-orange-500' : ''}>{h.disabled ? '無効' : ago(h.last_seen_at)}</td>
                  <td className={Number(h.k) ? 'font-semibold text-red-600' : ''}>{h.k}</td><td>{h.c}</td>
                  <td><Link className="text-muted underline" href={`/findings?host=${h.id}&all=1`}>{Number(h.total) - Number(h.k) - Number(h.c)}</Link></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        </>
      )}
    </Card>
    </>
  );
}
