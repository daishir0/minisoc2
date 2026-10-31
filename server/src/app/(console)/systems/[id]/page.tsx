import Link from 'next/link';
import { notFound } from 'next/navigation';
import { Card, Kev, Sev, ago, vulnLink } from '@/components/ui';
import { q, q1 } from '@/lib/db';
import { STACK_KEYS, detectStack } from '@/lib/systemmeta';
import { taskKey } from '@/lib/tasks';
import { addExclude, removeExclude, unregisterSystem } from '../../actions';
import { PendingButton } from '@/components/PendingButton';
import { SystemForm } from '../SystemForm';
import { Breadcrumbs, CRUMB } from '@/components/Breadcrumbs';
import { RemediationPicker } from '@/components/RemediationPicker';
import { ConfirmCollect } from '@/components/ConfirmCollect';
import { CopyBlock } from '@/components/CopyBlock';

export default async function SystemPage({ params, searchParams }: { params: Promise<{ id: string }>; searchParams: Promise<{ saved?: string }> }) {
  const { id } = await params;
  const { saved } = await searchParams;
  const s = await q1<{
    id: number; host_id: string; host: string; root: string; name: string; ignored: boolean; origin: string; exposure: string; criticality: string;
    url: string; owner: string; stack: string; note: string; first_seen: Date; last_seen: Date;
  }>('SELECT s.*, h.name AS host FROM systems s JOIN hosts h ON h.id=s.host_id WHERE s.id=$1', [Number(id) || 0]);
  if (!s) notFound();
  const eco = await q<{ ecosystem: string; n: string }>(
    'SELECT ecosystem, count(*) AS n FROM host_packages WHERE host_id=$1 AND $2 = ANY(systems) GROUP BY ecosystem ORDER BY 2 DESC', [s.host_id, s.root],
  );
  const markers = await q<{ k: string }>(
    "SELECT DISTINCT ecosystem || ':' || name AS k FROM host_packages WHERE host_id=$1 AND $2 = ANY(systems) AND ecosystem || ':' || name = ANY($3::text[])",
    [s.host_id, s.root, STACK_KEYS],
  );
  const detected = detectStack(markers.map((m) => m.k), eco.map((e) => e.ecosystem));
  // A finding's `version` is aggregated across the whole host (all projects sharing the package),
  // so per-system views must show only the versions actually installed UNDER this system's root that
  // are vulnerable to this CVE — otherwise other projects' versions leak into the display/prompt.
  const sysVersion = `COALESCE((SELECT string_agg(DISTINCT p.version, ', ' ORDER BY p.version) FROM host_packages p
       WHERE p.host_id=f.host_id AND p.ecosystem=f.ecosystem AND p.name=f.pkg AND $2 = ANY(p.systems)
         AND p.version = ANY(string_to_array(f.version, ', '))), f.version)`;
  const top = await q<{ vuln_id: string; pkg: string; version: string; fixed: string; severity: string; kev: boolean }>(
    `SELECT f.vuln_id, f.pkg, ${sysVersion} AS version, f.fixed, f.severity, f.kev FROM findings f WHERE f.host_id=$1 AND f.status='open' AND $2 = ANY(f.systems)
     ORDER BY f.kev DESC, CASE f.severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END LIMIT 10`,
    [s.host_id, s.root],
  );
  const excludes = await q<{ id: number; pattern: string; reason: string; created_by: string; created_at: Date; review: string | null; n: string }>(
    `SELECT e.id, e.pattern, e.reason, e.created_by, e.created_at, to_char(e.review_date, 'YYYY-MM-DD') AS review,
       (SELECT count(*) FROM host_packages_excluded x WHERE x.host_id=$2 AND x.system_root=$3 AND x.pattern=e.pattern) AS n
     FROM system_excludes e WHERE e.system_id=$1 ORDER BY e.pattern`,
    [s.id, s.host_id, s.root],
  );
  const services = await q<{ name: string; runtime_root: string | null; os_pkg: string | null }>(
    'SELECT name, runtime_root, os_pkg FROM host_services WHERE host_id=$1 AND system_root=$2 ORDER BY name', [s.host_id, s.root],
  );
  const cnt = async (where: string, params: unknown[]) =>
    (await q<{ kev: string; crit: string }>(`SELECT count(*) FILTER (WHERE kev) AS kev, count(*) FILTER (WHERE NOT kev AND severity='critical') AS crit FROM findings WHERE host_id=$1 AND status='open' AND (kev OR severity='critical') AND ${where}`, [s.host_id, ...params]))[0];
  const own = await cnt('$2 = ANY(systems)', [s.root]);
  const runtimes = [...new Set(services.map((x) => x.runtime_root).filter((x): x is string => !!x && x !== s.root))];
  const runtimeRows = await Promise.all(runtimes.map(async (r) => ({ root: r, name: (await q1<{ name: string }>('SELECT name FROM systems WHERE host_id=$1 AND root=$2', [s.host_id, r]))?.name ?? r, ...(await cnt('$2 = ANY(systems)', [r])) })));
  const osPkgs = [...new Set(services.map((x) => x.os_pkg).filter((x): x is string => !!x))];
  const osRow = osPkgs.length ? await cnt("source='os-advisory' AND (pkg = ANY($2) OR EXISTS (SELECT 1 FROM unnest($2::text[]) o WHERE pkg LIKE o || '-%'))", [osPkgs]) : { kev: '0', crit: '0' };
  const wideRow = await cnt("source='os-advisory' AND pkg ~ '^(kernel|glibc|openssl|systemd|zlib|sudo|openssh)'", []);
  const total = await q1<{ n: string }>("SELECT count(*) AS n FROM findings WHERE host_id=$1 AND status='open' AND $2 = ANY(systems)", [s.host_id, s.root]);
  // open findings of this project + the host address, for the Claude Code remediation prompt picker
  const picks = await q<{ id: string; vuln_id: string; pkg: string; version: string; fixed: string; severity: string; kev: boolean }>(
    `SELECT f.id, f.vuln_id, f.pkg, ${sysVersion} AS version, f.fixed, f.severity, f.kev FROM findings f WHERE f.host_id=$1 AND f.status='open' AND $2 = ANY(f.systems)
     ORDER BY f.kev DESC, CASE f.severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END LIMIT 300`,
    [s.host_id, s.root]);
  const hinfo = await q1<{ hostname: string; kind: string; ssh_host: string | null; last_seen_at: Date | null; ws_seen_at: Date | null;
    agent_meta: { invoke?: string; root?: boolean } | null; agent_config: { aide?: boolean; aidePaths?: string[] } | null }>(
    'SELECT h.hostname, h.kind, h.last_seen_at, h.ws_seen_at, h.agent_meta, h.agent_config, pt.ssh_host FROM hosts h LEFT JOIN pull_targets pt ON pt.host_id=h.id WHERE h.id=$1', [s.host_id]);
  const address = hinfo?.kind === 'pull' ? (hinfo.ssh_host ?? '') : (hinfo?.hostname ?? '');
  const wsOnline = !!hinfo?.ws_seen_at && Date.now() - new Date(hinfo.ws_seen_at).getTime() < 75_000;
  // File-integrity coverage for this project: is its root under the host's AIDE paths? Adding a path
  // widens what the agent hashes, so (per the config-push security model) it is applied ON THE HOST
  // via SSH, not pushed from the server. We show the status and generate the exact command.
  const aideEnabled = hinfo?.kind !== 'pull' && hinfo?.agent_config?.aide !== false;
  const aidePaths = hinfo?.agent_config?.aidePaths ?? [];
  const aideCovered = s.root !== '__os__' && aidePaths.some((p) => { const b = p.replace(/\/+$/, ''); return s.root === b || s.root.startsWith(b + '/'); });
  const aideP = `${hinfo?.agent_meta?.root ? 'sudo ' : ''}${hinfo?.agent_meta?.invoke ?? 'minisoc2-agent'}`;
  const aideAddCmd = `${aideP} config --aide-paths ${[...new Set([...aidePaths, s.root])].join(',')} && ${aideP} run`;

  return (
    <>
      <Breadcrumbs items={[CRUMB.home, CRUMB.assets, { label: s.host, href: `/hosts/${s.host_id}` }, { label: s.name }]} />
      <div className="flex flex-wrap items-center gap-3">
        <h1 className="text-xl font-semibold">{s.name}</h1>
        {s.ignored && <span className="rounded bg-slate-500 px-2 py-0.5 text-xs text-white">除外中</span>}
        <span className="text-sm text-muted">{s.host} · {s.root === '__os__' ? 'OSのパッケージマネージャ' : <span className="break-all font-mono">{s.root}</span>}</span>
      </div>
      {saved && (
        <div className="rounded-md border border-green-500 bg-green-50 px-3 py-2 text-sm text-green-700 dark:bg-green-950 dark:text-green-200">
          保存しました。登録済みプロジェクトとして評価対象になります（次回の照合から反映）。
          <div className="mt-1 flex gap-3">
            <Link href={`/hosts/${s.host_id}`} className="text-accent">← {s.host} に戻る（他の候補を登録）</Link>
            <Link href="/hosts" className="text-accent">資産（ホスト一覧）へ</Link>
          </div>
        </div>
      )}
      {s.root !== '__os__' && (
        <Card title="このシステムに影響する脆弱性（KEV・緊急）">
          <ul className="divide-y divide-line text-sm">
            {[
              { label: '自前の依存', sub: 'lockfile・venv', row: own, href: `/actions/${taskKey(s.host_id, s.root)}`, certainty: '' },
              ...runtimeRows.map((r) => ({ label: `実行環境：${r.name}`, sub: 'サービスが使用', row: r, href: `/actions/${taskKey(s.host_id, r.root)}`, certainty: '' })),
              ...(osPkgs.length ? [{ label: `OS：${osPkgs.join('、')}`, sub: 'サービスの実行ファイル', row: osRow, href: `/actions/${taskKey(s.host_id, '__os__')}`, certainty: '' }] : []),
              { label: 'OS：kernel・openssl など', sub: 'ホスト全体', row: wideRow, href: `/actions/${taskKey(s.host_id, '__os__')}`, certainty: '推定' },
            ].map((x, i) => (
              <li key={i} className="flex flex-wrap items-center gap-2 py-2">
                <span className="font-medium">{x.label}</span>
                <span className="text-xs text-muted">{x.sub}</span>
                {x.certainty && <span className="rounded bg-bg px-1.5 py-0.5 text-[11px] text-muted">{x.certainty}</span>}
                <span className="ml-auto">
                  {Number(x.row.kev) + Number(x.row.crit) === 0 ? <span className="text-muted">なし</span> : (
                    <Link href={x.href} className="text-accent">{Number(x.row.kev) ? <b className="text-red-600">KEV {x.row.kev}</b> : null}{Number(x.row.kev) && Number(x.row.crit) ? '・' : ''}{Number(x.row.crit) ? `緊急 ${x.row.crit}` : ''} → 作業へ</Link>
                  )}
                </span>
              </li>
            ))}
          </ul>
          <p className="mt-2 text-xs text-muted">稼働中のサービス：{services.length ? services.map((x) => x.name.replace(/\.service$/, '')).join('、') : '見つかりません（サービスとして動いていないか、エージェントが 0.7.0 未満です）'}</p>
        </Card>
      )}

      {s.root !== '__os__' && picks.length > 0 && (
        <Card title="Claude Code で解消（CVEを選んでプロンプト生成）">
          <p className="mb-3 text-sm text-muted">
            解消したいCVEにチェックを入れると、<b>対象ホスト上で <code>claude</code>（Claude Code）に貼り付けて実行できる</b>、バックアップ前提の安全なアップグレード提案プロンプトを生成します。内容を確認のうえ対象ホストで実行してください（minisoc2 がサーバーから実行することはありません）。
          </p>
          <RemediationPicker host={s.host} address={address} path={s.root} system={s.name}
            findings={picks.map((f) => ({ id: String(f.id), cve: f.vuln_id, pkg: f.pkg, version: f.version, fixed: f.fixed, severity: f.severity, kev: f.kev }))} />
          {hinfo?.kind !== 'pull' && (
            <div className="mt-4 border-t border-line pt-3">
              <p className="mb-2 text-xs text-muted">対処（アップグレード）が終わったら、ここで収集を促すと解消が反映されます。</p>
              <ConfirmCollect hostId={s.host_id} online={wsOnline} lastSeenAt={hinfo?.last_seen_at ? new Date(hinfo.last_seen_at).toISOString() : null} label="対処を確認（今すぐ収集）" />
            </div>
          )}
        </Card>
      )}

      <div className="grid gap-6 lg:grid-cols-3">
        <div className="lg:col-span-2">
          <Card title="登録内容"><SystemForm v={{ ...s, hostId: s.host_id, detectedStack: detected }} /></Card>
        </div>
        <div className="space-y-6">
          <Card title="概要">
            <dl className="grid grid-cols-[auto_1fr] gap-x-4 gap-y-1 text-sm">
              <dt className="text-muted">技術スタック</dt><dd>{s.stack || detected || '-'}</dd>
              <dt className="text-muted">パッケージ</dt><dd>{eco.map((e) => `${e.ecosystem} ${e.n}`).join(' / ') || '0'}</dd>
              <dt className="text-muted">未対応の脆弱性</dt><dd><Link className="text-accent" href={`/findings?host=${s.host_id}&system=${encodeURIComponent(s.root)}`}>{total?.n ?? 0}件</Link></dd>
              <dt className="text-muted">検出</dt><dd>{s.origin === 'manual' ? '手動登録' : '自動検出'}・初回 {ago(s.first_seen)}</dd>
              <dt className="text-muted">最終確認</dt><dd>{ago(s.last_seen)}</dd>
            </dl>
          </Card>
          <Card title="SBOM（CycloneDX 1.6）">
            <p className="mb-2 text-xs text-muted">自前の依存・使っている実行環境・OS の部品を含みます。除外したパッケージも「除外」の印と理由つきで残します。</p>
            <div className="flex flex-wrap gap-2">
              <a href={`/api/sbom?system=${s.id}`} className="btn-ghost">SBOM を出力</a>
              <a href={`/api/sbom?system=${s.id}&vex=1`} className="btn-ghost">SBOM＋VEX を出力</a>
            </div>
          </Card>
          {s.origin === 'manual' && s.root !== '__os__' && (
            <Card title="監視対象から外す">
              <p className="mb-2 text-xs text-muted">登録を解除すると<b>評価の対象外</b>になり、未対応の脆弱性は次回の照合で解消扱いになります。設定（除外パスなど）は保持され、<b>未登録の候補</b>に戻ります（再登録で元に戻せます）。</p>
              <form action={unregisterSystem}><input type="hidden" name="id" value={s.id} /><PendingButton className="btn-ghost text-red-600" pendingText="解除中…">監視対象から外す（登録解除）</PendingButton></form>
            </Card>
          )}
        </div>
      </div>
      {s.root !== '__os__' && (
        <Card title={`除外するパス${excludes.length ? `（${excludes.length}）` : ''}`}>
          <p className="mb-3 text-sm text-muted">
            このシステムが検証用などの目的で<b>あえて中に持っている</b>脆弱なアプリやサンプルを、場所（パス）で除外します。除外したパッケージは数えず通知もしませんが、件数は記録に残ります。反映はホストの次回の報告からです。
          </p>
          {excludes.length > 0 && (
            <ul className="mb-4 divide-y divide-line text-sm">
              {excludes.map((e) => (
                <li key={e.id} className="flex flex-col gap-1 py-2 sm:flex-row sm:items-center">
                  <div className="min-w-0 flex-1">
                    <span className="font-mono">{e.pattern}</span>
                    <span className="ml-2 text-xs text-muted">除外中のパッケージ {e.n}件</span>
                    <div className="text-xs text-muted">理由：{e.reason} ・ {e.created_by} ・ {new Date(e.created_at).toLocaleDateString('ja-JP')}{e.review ? ` ・ 見直し期限 ${e.review}` : ''}</div>
                  </div>
                  <form action={removeExclude}><input type="hidden" name="id" value={e.id} /><button className="btn-ghost">解除</button></form>
                </li>
              ))}
            </ul>
          )}
          <form action={addExclude} className="grid gap-2 sm:grid-cols-[1fr_1fr_auto_auto]">
            <input type="hidden" name="systemId" value={s.id} />
            <input name="pattern" className="input font-mono" placeholder="data/**" required />
            <input name="reason" className="input" placeholder="理由（例：検証用の脆弱なアプリ）" required />
            <input name="review" type="date" className="input" title="見直し期限（任意）" />
            <button className="btn">除外を追加</button>
          </form>
          <p className="mt-2 text-xs text-muted">書き方：<code>data/**</code>（data 配下すべて）、<code>research/**/corpus*/**</code>、<code>test-fixtures</code>。場所はこのシステムのルートからの相対パスです。</p>
        </Card>
      )}

      {s.root !== '__os__' && hinfo?.kind !== 'pull' && (
        <Card title="ファイル改ざん監視（このプロジェクト）">
          {!aideEnabled ? (
            <p className="text-sm text-muted">このホストではファイル改ざん検知が無効です（ホスト側 <code>minisoc2-agent config --aide on</code> で有効化できます）。</p>
          ) : aideCovered ? (
            <p className="text-sm text-green-600">✅ このプロジェクトのディレクトリは改ざん監視に含まれています。配下のファイルが変更・追加・削除されると検知します。</p>
          ) : (
            <>
              <p className="mb-2 text-sm text-muted">
                このプロジェクトのディレクトリは<b>まだ改ざん監視に含まれていません</b>。含めると配下のファイル改ざん（Web改ざん・Webshell 設置など）を検知できます。
                監視範囲の拡大は<b>内容をハッシュ化するため、サーバーからは配布せず</b>、ホスト上で次を実行して適用します（本システムのセキュリティ方針）。
              </p>
              <CopyBlock text={aideAddCmd} />
              <p className="mt-2 text-xs text-muted">※ 大きなデータ/ログを含むディレクトリは「除外するパス」で絞ると、スキャンの打ち切りを防げます。</p>
            </>
          )}
        </Card>
      )}

      <Card title="優先して対応すべき脆弱性（上位10件）">
        {top.length === 0 ? <p className="text-sm text-muted">未対応の脆弱性はありません。</p> : (
          <ul className="divide-y divide-line text-sm">
            {top.map((f) => (
              <li key={f.vuln_id + f.pkg} className="flex flex-wrap items-center gap-2 py-2">
                <Sev s={f.severity} />{f.kev && <Kev />}{vulnLink(f.vuln_id)}
                <span className="font-mono text-xs">{f.pkg} {f.version.slice(0, 40)}</span>
                {f.fixed && <span className="text-xs text-muted">→ {f.fixed.slice(0, 40)}</span>}
              </li>
            ))}
          </ul>
        )}
      </Card>
    </>
  );
}
