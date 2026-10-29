import Link from 'next/link';
import { notFound } from 'next/navigation';
import { Card, Sev, ago } from '@/components/ui';
import { q, q1 } from '@/lib/db';
import type { HostState } from '@/lib/payload';
import { hostAction, pollPullNow, savePullAide } from '../../actions';
import { PendingButton } from '@/components/PendingButton';

export default async function HostPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  if (!/^[0-9a-f-]{36}$/.test(id)) notFound();
  const h = await q1<{
    id: string; name: string; hostname: string; platform: string; os_name: string; os_version: string; kernel: string; arch: string;
    agent_version: string; enrolled_at: Date; last_seen_at: Date | null; disabled: boolean; state: Partial<HostState>; system_roots: string[]; allowed_ips: string[]; file_baseline_at: Date | null; kind: string;
  }>('SELECT * FROM hosts WHERE id=$1', [id]);
  if (!h) notFound();
  const pull = h.kind === 'pull'
    ? await q1<{ ssh_host: string; ssh_port: number; ssh_user: string; auth: string; every_hours: number; last_poll_at: Date | null; last_error: string | null; aide_paths: string[]; aide_excludes: string[] }>(
      'SELECT ssh_host, ssh_port, ssh_user, auth, every_hours, last_poll_at, last_error, aide_paths, aide_excludes FROM pull_targets WHERE host_id=$1', [id])
    : null;
  const fileBase = Number((await q<{ n: string }>('SELECT count(*) AS n FROM host_file_baseline WHERE host_id=$1', [id]))[0].n);
  const fileChanges = await q<{ created_at: Date; important: boolean; title: string }>(
    "SELECT ts AS created_at, important, title FROM change_events WHERE host_id=$1 AND kind='host_state' AND title LIKE '%監視ファイル%' ORDER BY ts DESC LIMIT 8", [id]);
  // Projects on this host: registered (manual) are evaluated; auto-detected are approval candidates.
  const projects = await q<{ id: number; root: string; name: string; origin: string; exposure: string; ignored: boolean; pkgs: string }>(
    `SELECT s.id, s.root, s.name, s.origin, s.exposure, s.ignored,
       (SELECT count(*) FROM host_packages p WHERE p.host_id=s.host_id AND s.root = ANY(p.systems)) AS pkgs
     FROM systems s WHERE s.host_id=$1 AND s.root <> '__os__' ORDER BY (s.origin='manual') DESC, s.name`, [id]);
  const registered = projects.filter((p) => p.origin === 'manual');
  const candidates = projects.filter((p) => p.origin !== 'manual');
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
        {h.kind === 'pull' && <span className="rounded bg-indigo-600 px-2 py-0.5 text-xs text-white">プル型（SSH）</span>}
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
          {registered.length === 0 && candidates.length > 0 && (
            <div className="mb-3 rounded-md border border-orange-400 bg-orange-50 px-3 py-2 text-xs text-orange-900 dark:bg-orange-950 dark:text-orange-100">
              ⚠ 評価は<b>登録済みプロジェクトだけ</b>に行います。このホストは未登録の候補が{candidates.length}件あり、<b>まだ評価されていません</b>。下の「プロジェクト」から登録すると、依存パッケージの脆弱性がここに表示されます。
            </div>
          )}
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
            <form action={hostAction}><input type="hidden" name="id" value={h.id} /><input type="hidden" name="op" value="rematch" /><PendingButton className="btn-ghost" pendingText="再照合中…" >今すぐ再照合</PendingButton></form>
            <form action={hostAction}><input type="hidden" name="id" value={h.id} /><input type="hidden" name="op" value={h.disabled ? 'enable' : 'disable'} /><button className="btn-ghost">{h.disabled ? '有効にする' : (pull ? '無効にする（収集を停止）' : '無効にする（報告を拒否）')}</button></form>
          </div>
          <p className="mt-1 text-xs text-muted">「今すぐ再照合」＝取得済みのインベントリを使って脆弱性を今すぐ再判定します（新しく公表されたCVEや設定変更の反映に使います。ホストへは接続しません）。「無効にする」＝{pull ? 'このホストの定期収集を止めます' : 'このホストからのAPI報告を拒否します'}。</p>
          {!pull && (
            <form action={hostAction} className="mt-3 space-y-1">
              <input type="hidden" name="id" value={h.id} /><input type="hidden" name="op" value="allowips" />
              <span className="block text-xs text-muted">許可する接続元IP（エージェント型のみ）。<b>エージェントを配置したホストのIP</b>を入れると、そのIPからのAPI報告だけを受け付けます。空欄=制限なし。設定すると全体の既定より優先。CIDR可（例 203.0.113.0/24）、改行区切り。</span>
              <textarea className="input font-mono text-xs" name="allowedIps" rows={2} defaultValue={(h.allowed_ips ?? []).join('\n')} placeholder="203.0.113.0/24" />
              <PendingButton className="btn-ghost" pendingText="保存中…">許可IPを保存</PendingButton>
            </form>
          )}
          <form action={hostAction} className="mt-3 flex gap-2">
            <input type="hidden" name="id" value={h.id} /><input type="hidden" name="op" value="delete" />
            <input className="input" name="confirm" placeholder='確認のため delete と入力' /><button className="btn-ghost text-red-600">ホストを削除</button>
          </form>
        </Card>
      </div>
      <Card title={`プロジェクト（登録済み ${registered.length}／未登録の候補 ${candidates.length}）`}
        right={pull ? (
          <form action={pollPullNow}><input type="hidden" name="id" value={h.id} />
            <PendingButton className="btn-ghost text-xs" pendingText="収集中…（十数秒）">🔄 サーバーを再スキャンして候補を更新</PendingButton>
          </form>
        ) : undefined}>
        <p className="mb-3 text-sm text-muted">
          評価（SBOM・脆弱性・改ざん検知）は<b>登録済みプロジェクトだけ</b>に対して行います。未登録の候補は{pull ? 'SSH収集' : 'エージェントのスキャン'}から自動検出したものです。内容を確認して登録してください。
          {pull && <><br />サーバー側でフォルダをアーカイブ・追加した後は、右上の「再スキャン」で候補を最新化できます（接続と収集に十数秒かかります）。</>}
          <Link href={`/systems/new?host=${h.id}`} className="ml-1 text-accent">手動でプロジェクトを追加</Link>
        </p>
        <h3 className="mb-1 text-xs font-semibold text-muted">登録済み</h3>
        {registered.length ? (
          <ul className="mb-4 divide-y divide-border text-sm">
            {registered.map((p) => (
              <li key={p.id} className="flex flex-wrap items-center gap-2 py-1.5">
                <Link href={`/systems/${p.id}`} className="font-medium text-accent">{p.name}</Link>
                {p.ignored && <span className="rounded bg-slate-500 px-1.5 text-xs text-white">除外中</span>}
                <span className="font-mono text-xs text-muted">{p.root}</span>
                <span className="ml-auto text-xs text-muted">{p.pkgs} パッケージ</span>
              </li>
            ))}
          </ul>
        ) : <p className="mb-4 text-sm text-muted">まだ登録済みプロジェクトはありません。</p>}
        <h3 className="mb-1 text-xs font-semibold text-muted">未登録の候補</h3>
        {candidates.length ? (
          <ul className="divide-y divide-border text-sm">
            {candidates.map((p) => (
              <li key={p.id} className="flex flex-wrap items-center gap-2 py-1.5">
                <span className="font-medium">{p.name}</span>
                <span className="font-mono text-xs text-muted">{p.root}</span>
                <span className="ml-auto text-xs text-muted">{p.pkgs} パッケージ</span>
                <Link href={`/systems/${p.id}`} className="btn-ghost">内容を見て登録</Link>
              </li>
            ))}
          </ul>
        ) : <p className="text-sm text-muted">候補はありません。</p>}
      </Card>
      {pull && (
        <Card title="SSH接続の状態（プル型）">
          <p className="mb-2 text-xs text-muted">
            このホストはエージェントを置けないため、サーバーから<b>読み取り専用SSH</b>で定期的に収集しています。ここは<b>接続先と最終結果</b>の確認用です（収集の手動実行は上の「プロジェクト」欄の「🔄 再スキャン」から）。
          </p>
          <dl className="grid grid-cols-[auto_1fr] gap-x-4 gap-y-1 text-sm">
            <dt className="text-muted">接続先</dt><dd className="font-mono">{pull.ssh_user}@{pull.ssh_host}:{pull.ssh_port}（{pull.auth === 'key' ? '鍵' : 'パスワード'}）</dd>
            <dt className="text-muted">収集間隔</dt><dd>{pull.every_hours} 時間ごと</dd>
            <dt className="text-muted">最終収集</dt><dd>{ago(pull.last_poll_at)}</dd>
            <dt className="text-muted">状態</dt><dd>{pull.last_error ? <span className="text-red-600">エラー</span> : <span className="text-green-600">正常</span>}</dd>
            {pull.last_error && <><dt className="text-red-600">詳細</dt><dd className="break-all text-red-600">{pull.last_error}</dd></>}
          </dl>
        </Card>
      )}
      <Card title="ファイル改ざん検知（AIDE相当）">
        {fileBase === 0 ? (
          <p className="text-sm text-muted">{pull
            ? '下の「監視ディレクトリ」を設定して「保存」すると、次回の収集でベースラインを確定します（未設定だと SSH鍵・crontab のみ監視）。'
            : <>まだベースラインがありません。エージェントが有効なら、次回の報告で確定します（ホスト側で <code>minisoc2-agent config --aide off</code> なら無効）。</>}</p>
        ) : (
          <>
            <p className="text-sm">
              <b>{fileBase.toLocaleString()}</b> ファイルを監視中
              {h.file_baseline_at && <span className="text-muted"> ・ ベースライン確定 {new Date(h.file_baseline_at).toISOString().slice(0, 10)}</span>}
              <span className="text-muted"> ・ 変化は自動でベースラインに反映（自動昇格）</span>
            </p>
            {fileChanges.length > 0 ? (
              <ul className="mt-2 divide-y divide-border text-sm">
                {fileChanges.map((e, i) => (
                  <li key={i} className="flex items-center gap-2 py-1.5">
                    {e.important && <span className="rounded bg-red-600 px-1.5 text-xs text-white">重要</span>}
                    <span className="min-w-0 flex-1 truncate">{e.title}</span>
                    <span className="whitespace-nowrap text-xs text-muted">{ago(e.created_at)}</span>
                  </li>
                ))}
              </ul>
            ) : <p className="mt-2 text-sm text-muted">ベースライン確定後、変化は検出されていません。</p>}
          </>
        )}
        {pull && (
          <form action={savePullAide} className="mt-4 space-y-2 border-t border-line pt-3">
            <input type="hidden" name="id" value={h.id} />
            <h3 className="text-xs font-semibold text-muted">監視ディレクトリ（複数可・改行区切り）</h3>
            <p className="text-xs text-muted">この配下のファイルを読み取り専用でハッシュし、改ざんを検知します。例：<code>~/www/path-finder.jp</code>、<code>~/bin</code>。空欄なら SSH鍵・crontab のみ。</p>
            <textarea name="aidePaths" rows={3} className="input font-mono text-xs" defaultValue={(pull.aide_paths ?? []).join('\n')} placeholder={'~/www/path-finder.jp\n~/bin'} />
            <h3 className="text-xs font-semibold text-muted">除外するサブディレクトリ（複数可・改行区切り）</h3>
            <p className="text-xs text-muted">上の監視対象から外すパス。例：<code>~/www/path-finder.jp/cache</code>、<code>~/www/blog.path-finder.jp/wp-content/uploads</code>（node_modules・.git・vendor は自動除外）。</p>
            <textarea name="aideExcludes" rows={2} className="input font-mono text-xs" defaultValue={(pull.aide_excludes ?? []).join('\n')} placeholder={'~/www/path-finder.jp/wp-content/cache'} />
            <PendingButton className="btn-ghost" pendingText="保存中…">保存（次回の収集から反映）</PendingButton>
          </form>
        )}
      </Card>
      <div className="grid gap-6 lg:grid-cols-2">
        {!pull && (
        <Card title={`待受ポート（${ports.length}）`}>
          <p className="mb-2 text-xs text-muted">このホストで外部からの接続を待ち受けているポートです。身に覚えのないポートは侵入やバックドアの兆候になります。</p>
          <div className="max-h-72 overflow-y-auto">
            <table className="tbl"><thead><tr><th>プロトコル</th><th>アドレス</th><th>ポート</th></tr></thead><tbody>
              {ports.map((p) => <tr key={`${p.proto}${p.addr}${p.port}`}><td>{p.proto}</td><td className="font-mono text-xs">{p.addr}</td><td>{p.port}</td></tr>)}
            </tbody></table>
          </div>
          <p className="mt-2 text-xs text-muted">ログイン可能なアカウント： {(h.state.users ?? []).join(', ') || '-'}</p>
        </Card>
        )}
        <Card title={pull ? '収集の履歴' : '直近の報告'}>
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
