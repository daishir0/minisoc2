import Link from 'next/link';
import { notFound } from 'next/navigation';
import { Card, Sev, ago } from '@/components/ui';
import { q, q1 } from '@/lib/db';
import type { HostState } from '@/lib/payload';
import { hostAction } from '../../actions';

export default async function HostPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  if (!/^[0-9a-f-]{36}$/.test(id)) notFound();
  const h = await q1<{
    id: string; name: string; hostname: string; platform: string; os_name: string; os_version: string; kernel: string; arch: string;
    agent_version: string; enrolled_at: Date; last_seen_at: Date | null; disabled: boolean; state: Partial<HostState>; system_roots: string[];
  }>('SELECT * FROM hosts WHERE id=$1', [id]);
  if (!h) notFound();
  const sev = await q<{ severity: string; n: string }>("SELECT severity, count(*) AS n FROM findings WHERE host_id=$1 AND status='open' GROUP BY severity", [id]);
  const eco = await q<{ ecosystem: string; n: string }>('SELECT ecosystem, count(*) AS n FROM host_packages WHERE host_id=$1 GROUP BY ecosystem ORDER BY 2 DESC', [id]);
  const reports = await q<{ received_at: Date; agent_version: string; duration_ms: number; package_count: number; advisory_count: number | null; errors: { step: string; message: string }[]; update_info: { error?: string } | null }>(
    'SELECT received_at, agent_version, duration_ms, package_count, advisory_count, errors, update_info FROM reports WHERE host_id=$1 ORDER BY received_at DESC LIMIT 10', [id],
  );
  const by = Object.fromEntries(sev.map((r) => [r.severity, r.n]));
  const kevN = Number((await q<{ n: string }>("SELECT count(*) AS n FROM findings WHERE host_id=$1 AND status='open' AND kev", [id]))[0].n);
  const ports = h.state.ports ?? [];

  return (
    <>
      <div className="text-sm text-muted"><Link href="/hosts" className="text-accent">資産</Link> › ホスト › {h.name}</div>
      <div className="flex flex-wrap items-center gap-3">
        <h1 className="text-xl font-semibold">{h.name}</h1>
        {h.disabled && <span className="rounded bg-slate-500 px-2 py-0.5 text-xs text-white">無効</span>}
        <Link className="btn-ghost ml-auto" href={`/findings?host=${h.id}`}>未対応の脆弱性</Link>
      </div>
      <div className="grid gap-6 lg:grid-cols-3">
        <Card title="ホスト情報">
          <dl className="grid grid-cols-[auto_1fr] gap-x-4 gap-y-1 text-sm">
            <dt className="text-muted">ホスト名</dt><dd className="break-all">{h.hostname}</dd>
            <dt className="text-muted">OS</dt><dd>{h.os_name} {h.os_version} ({h.arch})</dd>
            <dt className="text-muted">カーネル</dt><dd className="break-all">{h.kernel}</dd>
            <dt className="text-muted">エージェント</dt><dd>{h.agent_version}</dd>
            <dt className="text-muted">登録日</dt><dd>{new Date(h.enrolled_at).toISOString().slice(0, 10)}</dd>
            <dt className="text-muted">最終報告</dt><dd>{ago(h.last_seen_at)}</dd>
            <dt className="text-muted">ホストID</dt><dd className="font-mono text-xs">{h.id}</dd>
          </dl>
        </Card>
        <Card title="未対応の脆弱性">
          <div className="flex flex-wrap gap-4 text-sm">
            <Link href={`/findings?host=${h.id}&kev=1`} className={kevN ? 'font-semibold text-red-600' : ''}>KEV {kevN}</Link>
            <Link href={`/findings?host=${h.id}&severity=critical`} className="flex items-center gap-1"><Sev s="critical" /> {by.critical ?? 0}</Link>
          </div>
          <details className="mt-2 text-sm">
            <summary className="cursor-pointer text-muted">その他の深刻度</summary>
            <div className="mt-1 flex flex-wrap gap-3">
              {['high', 'medium', 'low', 'unknown'].map((s) => (
                <Link key={s} href={`/findings?host=${h.id}&severity=${s}`} className="flex items-center gap-1"><Sev s={s} /> {by[s] ?? 0}</Link>
              ))}
            </div>
          </details>
          <h3 className="mt-4 mb-1 text-xs font-semibold text-muted">インベントリ（パッケージ数）</h3>
          <ul className="text-sm">{eco.map((e) => <li key={e.ecosystem}>{e.ecosystem}: {e.n}</li>)}</ul>
        </Card>
        <Card title="管理">
          <form action={hostAction} className="flex gap-2">
            <input type="hidden" name="id" value={h.id} /><input type="hidden" name="op" value="rename" />
            <input className="input" name="name" defaultValue={h.name} /><button className="btn-ghost">名前を変更</button>
          </form>
          <div className="mt-3 flex flex-wrap gap-2">
            <form action={hostAction}><input type="hidden" name="id" value={h.id} /><input type="hidden" name="op" value="rematch" /><button className="btn-ghost">今すぐ再照合</button></form>
            <form action={hostAction}><input type="hidden" name="id" value={h.id} /><input type="hidden" name="op" value={h.disabled ? 'enable' : 'disable'} /><button className="btn-ghost">{h.disabled ? '有効にする' : '無効にする（報告を拒否）'}</button></form>
          </div>
          <form action={hostAction} className="mt-3 flex gap-2">
            <input type="hidden" name="id" value={h.id} /><input type="hidden" name="op" value="delete" />
            <input className="input" name="confirm" placeholder='確認のため delete と入力' /><button className="btn-ghost text-red-600">ホストを削除</button>
          </form>
        </Card>
      </div>
      <Card title="システム">
        <p className="text-sm text-muted">このホストの開発システムは<Link href="/systems" className="mx-1 text-accent">システム画面</Link>で確認・登録できます。</p>
      </Card>
      <div className="grid gap-6 lg:grid-cols-2">
        <Card title={`待受ポート（${ports.length}）`}>
          <div className="max-h-72 overflow-y-auto">
            <table className="tbl"><thead><tr><th>プロトコル</th><th>アドレス</th><th>ポート</th></tr></thead><tbody>
              {ports.map((p) => <tr key={`${p.proto}${p.addr}${p.port}`}><td>{p.proto}</td><td className="font-mono text-xs">{p.addr}</td><td>{p.port}</td></tr>)}
            </tbody></table>
          </div>
          <p className="mt-2 text-xs text-muted">ログイン可能なアカウント： {(h.state.users ?? []).join(', ') || '-'}</p>
        </Card>
        <Card title="直近の報告">
          <table className="tbl"><thead><tr><th>日時</th><th>エージェント</th><th>パッケージ</th><th>OS修正</th><th>所要</th><th>問題</th></tr></thead><tbody>
            {reports.map((r) => (
              <tr key={String(r.received_at)}>
                <td className="whitespace-nowrap">{ago(r.received_at)}</td><td className="font-mono text-xs">{r.agent_version}</td><td>{r.package_count}</td><td>{r.advisory_count ?? '-'}</td><td className="whitespace-nowrap">{(r.duration_ms / 1000).toFixed(1)}s</td>
                <td className="text-xs text-orange-600">{[...r.errors.map((e) => `${e.step}: ${e.message}`), r.update_info?.error && `更新: ${r.update_info.error}`].filter(Boolean).join('\n') || '-'}</td>
              </tr>
            ))}
          </tbody></table>
        </Card>
      </div>
    </>
  );
}
