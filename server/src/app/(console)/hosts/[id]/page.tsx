import Link from 'next/link';
import type { ReactNode } from 'react';
import { notFound } from 'next/navigation';
import { Card, Sev, ago } from '@/components/ui';
import { CRITICALITY, EXPOSURE } from '@/lib/systemmeta';
import { q, q1 } from '@/lib/db';
import type { HostState } from '@/lib/payload';
import { hostAction, pollPullNow, registerSystem, savePullAide, unregisterSystem } from '../../actions';
import { PendingButton } from '@/components/PendingButton';
import { Breadcrumbs, CRUMB } from '@/components/Breadcrumbs';
import { taskKey } from '@/lib/tasks';
import { AgentConfigCard, type AgentConfig } from '@/components/AgentConfigCard';
import { ConfirmCollect } from '@/components/ConfirmCollect';
import { TrendChart, SparkLine, type TrendPoint } from '@/components/TrendChart';
import { agentDistDir } from '@/lib/agentdist';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';

// One remediation unit (kernel / non-kernel OS / a project env). This is the core repeated card of the
// host screen: status at a glance + one click into its remediation prompt. Kept generic (no host-specifics).
function UnitCard({ icon, title, sub, kev, crit, high, total, href, badge, trend }: {
  icon: string; title: string; sub?: string; kev: number; crit: number; high: number; total: number; href: string; badge?: ReactNode; trend?: TrendPoint[];
}) {
  const spark = trend?.map((p) => p.kev + p.critical + p.high + p.medium + p.low);
  const tone = kev > 0 || crit > 0 ? 'border-l-red-500' : high > 0 ? 'border-l-orange-400' : total > 0 ? 'border-l-yellow-400' : 'border-l-green-500';
  return (
    <div className={`flex flex-col gap-2 rounded-lg border border-line border-l-4 ${tone} bg-bg p-4`}>
      <div className="flex min-w-0 items-center gap-2">
        <span className="text-base">{icon}</span>
        <h3 className="truncate text-sm font-semibold">{title}</h3>
        {badge}
      </div>
      {sub && <p className="text-xs text-muted">{sub}</p>}
      <div className="flex flex-wrap items-center gap-x-3 gap-y-1 text-xs">
        {total > 0 ? (
          <>
            {kev > 0 && <span className="font-semibold text-red-600">KEV {kev}</span>}
            {crit > 0 && <span className="font-semibold text-red-600">緊急 {crit}</span>}
            {high > 0 && <span className="text-orange-600">高 {high}</span>}
            <span className="text-muted">計 {total}</span>
          </>
        ) : <span className="font-medium text-green-600">対処不要（未対応なし）</span>}
        {spark && spark.length > 1 && trend && <span className="ml-auto" title="クリックで拡大（日次の件数を表示）"><SparkLine values={spark} detail={{ points: trend, title: `${title} の推移` }} /></span>}
      </div>
      <div className="mt-auto pt-1">
        <Link href={href} className={total > 0 ? 'btn text-xs' : 'btn-ghost text-xs'}>{total > 0 ? '対応する →' : '詳細 →'}</Link>
      </div>
    </div>
  );
}

export default async function HostPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  if (!/^[0-9a-f-]{36}$/.test(id)) notFound();
  const h = await q1<{
    id: string; name: string; hostname: string; platform: string; os_name: string; os_version: string; kernel: string; arch: string;
    agent_version: string; enrolled_at: Date; last_seen_at: Date | null; disabled: boolean; state: Partial<HostState>; system_roots: string[]; allowed_ips: string[]; file_baseline_at: Date | null; kind: string;
    agent_config: AgentConfig | null; agent_meta: { invoke?: string; root?: boolean; home?: string; intervalHours?: number } | null;
    collect_requested: boolean; last_checkin_at: Date | null; ws_seen_at: Date | null;
  }>('SELECT * FROM hosts WHERE id=$1', [id]);
  if (!h) notFound();
  const wsOnline = !!h.ws_seen_at && Date.now() - new Date(h.ws_seen_at).getTime() < 75_000;
  let agentLatest = '';
  try { agentLatest = (JSON.parse(readFileSync(join(agentDistDir(), 'manifest.json'), 'utf8')) as { latest?: string }).latest ?? ''; } catch { /* no manifest */ }
  const pull = h.kind === 'pull'
    ? await q1<{ ssh_host: string; ssh_port: number; ssh_user: string; auth: string; every_hours: number; last_poll_at: Date | null; last_error: string | null; aide_paths: string[]; aide_excludes: string[] }>(
      'SELECT ssh_host, ssh_port, ssh_user, auth, every_hours, last_poll_at, last_error, aide_paths, aide_excludes FROM pull_targets WHERE host_id=$1', [id])
    : null;
  const fileBase = Number((await q<{ n: string }>('SELECT count(*) AS n FROM host_file_baseline WHERE host_id=$1', [id]))[0].n);
  // Per-host vulnerability trend (same stacked chart as the home page, scoped to this host).
  const htrend = await q<{ day: string; kev: string; critical: string; high: string; medium: string; low: string }>(
    `SELECT to_char(day, 'YYYY-MM-DD') AS day, sum(kev) AS kev, sum(critical) AS critical, sum(high) AS high, sum(medium) AS medium, sum(low) AS low FROM daily_snapshots ds
     WHERE host_id=$1 AND day > current_date - 90 AND NOT EXISTS (SELECT 1 FROM systems s WHERE s.host_id=ds.host_id AND s.root=ds.system_root AND s.ignored)
     GROUP BY day ORDER BY day`, [id]);
  const [hLive] = await q<{ kev: string; critical: string; high: string; medium: string; low: string }>(
    `SELECT count(*) FILTER (WHERE kev) AS kev, count(*) FILTER (WHERE NOT kev AND severity='critical') AS critical,
            count(*) FILTER (WHERE NOT kev AND severity='high') AS high, count(*) FILTER (WHERE severity='medium') AS medium,
            count(*) FILTER (WHERE severity='low') AS low FROM findings WHERE host_id=$1 AND status='open'`, [id]);
  const [{ resolved: hResolved }] = await q<{ resolved: string }>("SELECT count(*) AS resolved FROM findings WHERE host_id=$1 AND status='resolved'", [id]);
  const hToday = new Date().toISOString().slice(0, 10);
  const hPts = htrend.map((r) => ({ day: r.day, kev: Number(r.kev), critical: Number(r.critical), high: Number(r.high), medium: Number(r.medium), low: Number(r.low) }));
  if (!hPts.length || hPts[hPts.length - 1].day !== hToday) {
    hPts.push({ day: hToday, kev: Number(hLive.kev), critical: Number(hLive.critical), high: Number(hLive.high), medium: Number(hLive.medium), low: Number(hLive.low), live: true } as (typeof hPts)[number] & { live: boolean });
  }
  const fileChanges = await q<{ created_at: Date; important: boolean; title: string }>(
    "SELECT ts AS created_at, important, title FROM change_events WHERE host_id=$1 AND kind='host_state' AND title LIKE '%監視ファイル%' ORDER BY ts DESC LIMIT 8", [id]);
  // Projects on this host: registered (manual) are evaluated; auto-detected are approval candidates.
  const projects = await q<{ id: number; root: string; name: string; origin: string; exposure: string; criticality: string; stack: string; ignored: boolean; pkgs: string; k: string; c: string; hi: string; total: string }>(
    `SELECT s.id, s.root, s.name, s.origin, s.exposure, s.criticality, s.stack, s.ignored,
       (SELECT count(*) FROM host_packages p WHERE p.host_id=s.host_id AND s.root = ANY(p.systems)) AS pkgs,
       (SELECT count(*) FROM findings f WHERE f.host_id=s.host_id AND f.status='open' AND s.root = ANY(f.systems) AND f.kev) AS k,
       (SELECT count(*) FROM findings f WHERE f.host_id=s.host_id AND f.status='open' AND s.root = ANY(f.systems) AND NOT f.kev AND f.severity='critical') AS c,
       (SELECT count(*) FROM findings f WHERE f.host_id=s.host_id AND f.status='open' AND s.root = ANY(f.systems) AND NOT f.kev AND f.severity='high') AS hi,
       (SELECT count(*) FROM findings f WHERE f.host_id=s.host_id AND f.status='open' AND s.root = ANY(f.systems)) AS total
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
  const fixedN = Number((await q<{ n: string }>("SELECT count(*) AS n FROM findings WHERE host_id=$1 AND status='resolved' AND resolved_at IS NOT NULL", [id]))[0].n);
  // OS (host-wide) KEV/critical, with a direct link to the OS remediation task (dnf/apt prompt).
  const osRow = (await q<{ kev: string; crit: string; sid: number | null }>("SELECT count(*) FILTER (WHERE kev) AS kev, count(*) FILTER (WHERE NOT kev AND severity='critical') AS crit, (SELECT id FROM systems s WHERE s.host_id=$1 AND s.root='__os__') AS sid FROM findings WHERE host_id=$1 AND status='open' AND '__os__' = ANY(systems)", [id]))[0];
  // OS findings split by fix method (kernel = reboot; the rest = package/bulk update) for the unit cards.
  const osSplit = await q<{ kind: string; kev: string; crit: string; hi: string; total: string }>(
    `SELECT CASE WHEN pkg ~ '^(linux|kernel)([-.]|$)' THEN 'kernel' ELSE 'other' END AS kind,
            count(*) FILTER (WHERE kev) AS kev, count(*) FILTER (WHERE NOT kev AND severity='critical') AS crit,
            count(*) FILTER (WHERE NOT kev AND severity='high') AS hi, count(*) AS total
     FROM findings WHERE host_id=$1 AND status='open' AND '__os__' = ANY(systems) GROUP BY 1`, [id]);
  const osK = osSplit.find((r) => r.kind === 'kernel');
  const osO = osSplit.find((r) => r.kind === 'other');
  const osHref = osRow.sid ? `/systems/${osRow.sid}` : `/actions/${taskKey(h.id, '__os__')}`;
  // Per-unit (system_root) daily severity series — for the unit-card sparklines and their enlarge overlay.
  const unitSeries = await q<{ root: string; day: string; kev: string; critical: string; high: string; medium: string; low: string }>(
    `SELECT system_root AS root, to_char(day, 'YYYY-MM-DD') AS day, sum(kev) AS kev, sum(critical) AS critical, sum(high) AS high, sum(medium) AS medium, sum(low) AS low
     FROM daily_snapshots WHERE host_id=$1 AND day > current_date - 90 GROUP BY system_root, day ORDER BY day`, [id]);
  const seriesByRoot = new Map<string, TrendPoint[]>();
  for (const r of unitSeries) seriesByRoot.set(r.root, [...(seriesByRoot.get(r.root) ?? []), { day: r.day, kev: Number(r.kev), critical: Number(r.critical), high: Number(r.high), medium: Number(r.medium), low: Number(r.low) }]);
  const osTrend = seriesByRoot.get('__os__');
  // Audit trail: config pushes, updates and collect requests are logged as 'ops' change events (with
  // the admin's email). Surface them so distribution is accountable.
  const ops = await q<{ ts: Date; title: string }>("SELECT ts, title FROM change_events WHERE host_id=$1 AND kind='ops' ORDER BY ts DESC LIMIT 20", [id]);
  const ports = h.state.ports ?? [];

  return (
    <>
      <Breadcrumbs items={[CRUMB.home, CRUMB.assets, CRUMB.hosts, { label: h.name }]} />
      <div className="flex flex-wrap items-center gap-3">
        <h1 className="text-xl font-semibold">{h.name}</h1>
        {h.kind === 'pull' && <span className="rounded bg-indigo-600 px-2 py-0.5 text-xs text-white">プル型（SSH）</span>}
        {h.kind !== 'pull' && (
          <span className={`inline-flex items-center gap-1 rounded px-2 py-0.5 text-xs ${wsOnline ? 'bg-green-100 text-green-700 dark:bg-green-950 dark:text-green-200' : 'bg-slate-200 text-slate-600 dark:bg-slate-800 dark:text-slate-300'}`} title="制御チャネル（リアルタイム収集）の接続状態">
            <span className={`h-2 w-2 rounded-full ${wsOnline ? 'bg-green-500' : 'bg-slate-400'}`} />{wsOnline ? 'オンライン' : 'オフライン'}
          </span>
        )}
        {h.disabled && <span className="rounded bg-slate-500 px-2 py-0.5 text-xs text-white">無効</span>}
        <Link className="btn-ghost ml-auto" href={`/hosts/${h.id}/history`}>✅ 対処の記録{fixedN ? `（${fixedN}）` : ''}</Link>
        <Link className="btn-ghost" href={`/findings?host=${h.id}`}>未対応の脆弱性</Link>
      </div>
      <Card title="このホストの脆弱性の推移（90日・深刻度別の積み上げ）" right={<Link href={`/hosts/${h.id}/history`} className="text-xs text-accent">対処の記録</Link>}>
        <TrendChart points={hPts} resolvedTotal={Number(hResolved)} />
      </Card>

      <section className="space-y-3">
        <h2 className="text-sm font-semibold">対応ユニット（直し方ごと）— プロンプトをコピーして実施 → 収集で確認</h2>
        <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
          <UnitCard icon="🧩" title="カーネル" sub="要再起動・計画実行" kev={Number(osK?.kev ?? 0)} crit={Number(osK?.crit ?? 0)} high={Number(osK?.hi ?? 0)} total={Number(osK?.total ?? 0)} href={osHref} trend={osTrend} />
          <UnitCard icon="📦" title="カーネル以外のOS" sub="一括更新・サービス再起動のみ" kev={Number(osO?.kev ?? 0)} crit={Number(osO?.crit ?? 0)} high={Number(osO?.hi ?? 0)} total={Number(osO?.total ?? 0)} href={osHref} trend={osTrend} />
          {registered.map((p) => (
            <UnitCard key={p.id} icon="🧪" title={p.name} sub={p.stack || 'プロジェクト環境'}
              kev={Number(p.k)} crit={Number(p.c)} high={Number(p.hi)} total={Number(p.total)} href={`/systems/${p.id}`} trend={seriesByRoot.get(p.root)}
              badge={p.exposure === 'public' ? <span className="rounded bg-red-100 px-1.5 text-[11px] text-red-700 dark:bg-red-950 dark:text-red-200">{EXPOSURE.public}</span> : p.ignored ? <span className="rounded bg-slate-500 px-1.5 text-[11px] text-white">除外中</span> : undefined} />
          ))}
        </div>
        {registered.length === 0 && candidates.length > 0 && (
          <p className="text-xs text-muted">⚠ 未登録の候補が {candidates.length} 件あります。下の「⚙️ 設定・管理・詳細」→「プロジェクトの登録」で登録すると、ここにユニットとして並びます。</p>
        )}
        {registered.length === 0 && candidates.length === 0 && Number(osRow.kev) + Number(osRow.crit) + Number(osO?.total ?? 0) + Number(osK?.total ?? 0) === 0 && (
          <p className="text-xs text-muted">未対応の脆弱性はありません。</p>
        )}
      </section>

      <details className="rounded-lg border border-line">
        <summary className="cursor-pointer px-4 py-3 text-sm font-semibold">⚙️ 設定・管理・詳細（ホスト情報／プロジェクト登録／エージェント／監査ログ／改ざん検知／ポート など）</summary>
        <div className="space-y-6 border-t border-line p-4">
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
              <li key={p.id} className="flex flex-col gap-1 py-1.5 sm:flex-row sm:items-center sm:gap-2">
                <span className="flex min-w-0 flex-wrap items-center gap-1.5">
                  <Link href={`/systems/${p.id}`} className="font-medium text-accent">{p.name}</Link>
                  {p.exposure === 'public' && <span className="rounded bg-red-100 px-1.5 text-[11px] text-red-700 dark:bg-red-950 dark:text-red-200">{EXPOSURE.public}</span>}
                  {p.exposure !== 'public' && p.exposure !== 'unknown' && <span className="rounded bg-bg px-1.5 text-[11px] text-muted">{EXPOSURE[p.exposure]}</span>}
                  {p.criticality !== 'normal' && <span className="rounded bg-bg px-1.5 text-[11px] text-muted">{CRITICALITY[p.criticality]}</span>}
                  {p.stack && <span className="rounded bg-bg px-1.5 text-[11px] text-muted">{p.stack}</span>}
                  {p.ignored && <span className="rounded bg-slate-500 px-1.5 text-[11px] text-white">除外中</span>}
                  <span className="hidden font-mono text-xs text-muted md:inline">{p.root}</span>
                </span>
                <span className="ml-auto flex shrink-0 items-center gap-3 text-xs">
                  <span className="text-muted">pkg {p.pkgs}</span>
                  <span className={Number(p.k) ? 'font-semibold text-red-600' : 'text-muted'}>KEV {p.k}</span>
                  <span className={Number(p.c) ? 'text-orange-600' : 'text-muted'}>緊急 {p.c}</span>
                  <span className={Number(p.hi) ? 'text-yellow-600' : 'text-muted'}>高 {p.hi}</span>
                  <Link href={`/systems/${p.id}`} className="btn-ghost">編集</Link>
                  <form action={unregisterSystem}><input type="hidden" name="id" value={p.id} /><PendingButton className="btn-ghost text-red-600" pendingText="解除中…">はずす</PendingButton></form>
                </span>
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
                <Link href={`/systems/${p.id}`} className="btn-ghost">詳細</Link>
                <form action={registerSystem}><input type="hidden" name="id" value={p.id} /><PendingButton className="btn" pendingText="登録中…">登録</PendingButton></form>
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
      {h.kind !== 'pull' && (
        <Card title="今すぐ収集を要求（対処の確認）">
          <p className="mb-2 text-sm text-muted">
            定期収集を待たずに収集させます。<b>制御チャネル接続中なら数秒で反映</b>、未接続なら数分おきの軽量チェックインで受け取り1回だけフル収集します。対処後にこれを押すと、新しい報告が届き次第この画面が自動更新されます。
          </p>
          <ConfirmCollect hostId={h.id} online={wsOnline} lastSeenAt={h.last_seen_at ? new Date(h.last_seen_at).toISOString() : null} />
          <p className="mt-2 text-xs text-muted">
            最終チェックイン {h.last_checkin_at ? ago(h.last_checkin_at) : '未（エージェント 0.1.5 以降で対応）'}
          </p>
        </Card>
      )}
      {h.kind !== 'pull' && h.agent_config && (
        <Card title="エージェント設定・操作">
          <p className="mb-3 text-sm text-muted">サーバーから配布できるのは<b>収集を減らす方向の設定だけ</b>（除外の追加・無効化）です。スキャン対象やログ対象など<b>内容を読む設定はホスト上（SSH）でのみ</b>変更できます。</p>
          <AgentConfigCard cfg={h.agent_config} invoke={h.agent_meta?.invoke ?? ''} root={!!h.agent_meta?.root} version={h.agent_version} latest={agentLatest} intervalHours={h.agent_meta?.intervalHours} hostId={h.id} online={wsOnline} />
        </Card>
      )}
      <Card title={`操作ログ（配布・更新・収集の監査）${ops.length ? `（最近 ${ops.length}）` : ''}`}>
        {ops.length === 0 ? <p className="text-sm text-muted">まだ操作はありません。設定配布・更新・収集要求を行うと、実施者（メール）と日時がここに残ります。</p> : (
          <ul className="divide-y divide-line text-sm">
            {ops.map((o, i) => (
              <li key={i} className="flex flex-wrap items-center gap-2 py-1.5">
                <span className="whitespace-nowrap font-mono text-xs text-muted">{new Date(o.ts).toLocaleString('ja-JP')}</span>
                <span>{o.title}</span>
              </li>
            ))}
          </ul>
        )}
      </Card>
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
        </div>
      </details>
    </>
  );
}
