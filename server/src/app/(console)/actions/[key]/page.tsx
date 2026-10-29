import Link from 'next/link';
import { notFound } from 'next/navigation';
import { Card, Kev, Sev, vulnLink } from '@/components/ui';
import { q } from '@/lib/db';
import { EXPOSURE } from '@/lib/systemmeta';
import { listTasks, parseTaskKey } from '@/lib/tasks';
import { VEX_JUSTIFICATIONS, VEX_LABEL } from '@/lib/vex';
import { saveTask, taskNotAffected } from '../../actions';

export default async function TaskPage({ params, searchParams }: { params: Promise<{ key: string }>; searchParams: Promise<{ saved?: string }> }) {
  const { key } = await params;
  const { saved } = await searchParams;
  const k = parseTaskKey(decodeURIComponent(key));
  if (!k) notFound();
  const [t] = await listTasks({ hostId: k.hostId, root: k.root });
  if (!t) {
    return (
      <Card title="作業">
        <p className="text-sm text-green-600">✅ この作業の対象（KEV・緊急）はすべて解消されています。</p>
        <Link href="/actions" className="mt-3 inline-block text-sm text-accent">対応の一覧へ</Link>
      </Card>
    );
  }
  const findings = await q<{ id: string; vuln_id: string; pkg: string; version: string; fixed: string; severity: string; kev: boolean; cvss: string | null }>(
    `SELECT id, vuln_id, pkg, version, fixed, severity, kev, cvss FROM findings
     WHERE host_id=$1 AND status='open' AND (kev OR severity='critical')
       AND (CASE WHEN cardinality(systems)=0 THEN ARRAY['__os__'] ELSE systems END) @> ARRAY[$2]
     ORDER BY kev DESC, cvss DESC NULLS LAST LIMIT 300`,
    [k.hostId, k.root],
  );

  return (
    <>
      <div className="text-sm text-muted"><Link href="/actions" className="text-accent">対応</Link> › {t.host} › {t.root === '__os__' ? 'OS' : t.name}</div>
      <div className="flex flex-wrap items-center gap-2">
        <h1 className="text-xl font-semibold">{t.root === '__os__' ? `${t.host} の OS を更新` : `${t.host}／${t.name} の依存を更新`}</h1>
        {t.exposure === 'public' && <span className="rounded bg-red-100 px-1.5 py-0.5 text-xs text-red-700 dark:bg-red-950 dark:text-red-200">{EXPOSURE.public}</span>}
      </div>
      <p className="text-sm">この作業で {t.kev ? <b className="text-red-600">KEV {t.kev}件</b> : null}{t.kev && t.critical ? '・' : ''}{t.critical ? `緊急 ${t.critical}件` : ''} が解消します。{t.reboot && <b> kernel を含むため、更新後に再起動が必要です。</b>}</p>
      {saved && <p className="text-sm text-green-600">保存しました。</p>}

      <div className="grid gap-6 lg:grid-cols-3">
        <div className="min-w-0 space-y-6 lg:col-span-2">
          <Card title="手順">
            <p className="mb-2 text-sm text-muted">{t.root === '__os__' ? 'ホストで次を実行します（必要なパッケージだけを更新します）。' : `${t.root} で次を実行し、動作を確認してからデプロイします。`}</p>
            <pre className="select-all whitespace-pre-wrap break-all rounded bg-bg p-3 text-xs">{t.command}</pre>
            {t.reboot && <pre className="mt-2 select-all rounded bg-bg p-3 text-xs">sudo reboot</pre>}
            <p className="mt-2 text-xs text-muted">更新後、次のエージェントの報告（最大1時間）で自動的に「解消」になります。</p>
          </Card>
          <Card title={`この作業で守られるシステム（${t.protects.length}）`}>
            {t.protects.length === 0 ? <p className="text-sm text-muted">このホストで、この修正に関係するサービスは見つかりませんでした。</p> : (
              <ul className="divide-y divide-line text-sm">
                {t.protects.map((p, i) => (
                  <li key={i} className="flex flex-wrap items-center gap-2 py-1.5">
                    {p.systemId ? <Link href={`/systems/${p.systemId}`} className="font-medium text-accent">{p.name}</Link> : <span className="font-medium">{p.name}</span>}
                    {p.exposure === 'public' && <span className="rounded bg-red-100 px-1.5 py-0.5 text-[11px] text-red-700 dark:bg-red-950 dark:text-red-200">{EXPOSURE.public}</span>}
                    {p.certainty === 'estimated' && <span className="rounded bg-bg px-1.5 py-0.5 text-[11px] text-muted">推定</span>}
                    <span className="text-xs text-muted">{p.via}</span>
                  </li>
                ))}
              </ul>
            )}
            <p className="mt-2 text-xs text-muted">稼働中のサービス（systemd）の作業ディレクトリと実行ファイルから判定しています。「推定」は kernel など、ホスト上のすべてに影響する部品です。</p>
          </Card>
          <Card title={`更新するパッケージ（${t.packages.length}）`}>
            <table className="tbl"><thead><tr><th>パッケージ</th><th>現在</th><th>更新先</th><th>KEV</th><th>緊急</th></tr></thead><tbody>
              {t.packages.map((p) => (
                <tr key={p.ecosystem + p.name}><td className="break-all font-mono text-xs">{p.name}</td><td className="font-mono text-xs">{p.current.slice(0, 40)}</td><td className="font-mono text-xs">{p.target || '-'}</td><td className={p.kev ? 'font-semibold text-red-600' : 'text-muted'}>{p.kev || ''}</td><td className="text-muted">{p.critical || ''}</td></tr>
              ))}
            </tbody></table>
          </Card>
          <Card title={`含まれる脆弱性（${findings.length}）`}>
            <ul className="divide-y divide-line text-sm">
              {findings.map((f) => (
                <li key={f.id} className="flex flex-wrap items-center gap-2 py-1.5">
                  <Sev s={f.severity} />{f.kev && <Kev />}{vulnLink(f.vuln_id)}
                  {f.cvss && <span className="text-xs text-muted">CVSS {f.cvss}</span>}
                  <span className="font-mono text-xs text-muted">{f.pkg}</span>
                </li>
              ))}
            </ul>
          </Card>
        </div>
        <div className="min-w-0 space-y-6">
          <Card title="状態">
            <form action={saveTask} className="space-y-3 text-sm">
              <input type="hidden" name="key" value={t.key} />
              <label className="block"><span className="mb-1 block text-muted">状態</span>
                <select name="status" defaultValue={t.status} className="input"><option value="todo">未着手</option><option value="doing">対応中</option><option value="hold">保留（期限まで一覧から外す）</option></select>
              </label>
              <label className="block"><span className="mb-1 block text-muted">担当</span><input name="owner" defaultValue={t.owner} className="input" /></label>
              <label className="block"><span className="mb-1 block text-muted">期限</span><input name="due" type="date" defaultValue={t.due ?? ''} className="input" /></label>
              <label className="block"><span className="mb-1 block text-muted">メモ</span><textarea name="note" rows={3} defaultValue={t.note} className="input" /></label>
              <button className="btn">保存</button>
            </form>
          </Card>
          <Card title="影響なしとして記録">
            <p className="mb-2 text-xs text-muted">この作業の脆弱性をまとめて「影響なし」（VEX）にします。理由は記録に残り、VEX として出力できます。</p>
            <form action={taskNotAffected} className="space-y-2">
              <input type="hidden" name="key" value={t.key} />
              <select name="reason" className="input" required>{VEX_JUSTIFICATIONS.map((j) => <option key={j} value={j}>{VEX_LABEL[j]}</option>)}</select>
              <input name="note" className="input" placeholder="判断の理由" required />
              <button className="btn-ghost">影響なしとして記録</button>
            </form>
          </Card>
        </div>
      </div>
    </>
  );
}
