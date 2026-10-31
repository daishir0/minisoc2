import { Breadcrumbs, CRUMB } from '@/components/Breadcrumbs';
import Link from 'next/link';
import { Card, ago } from '@/components/ui';
import { CRITICALITY, EXPOSURE } from '@/lib/systemmeta';
import { q } from '@/lib/db';
import { collectAllHosts, rematchAllHosts } from '../actions';

export default async function HostsPage() {
  const hosts = await q<{
    id: string; name: string; hostname: string; kind: string; os_name: string; os_version: string; agent_version: string;
    last_seen_at: Date | null; stale_alerted: boolean; disabled: boolean; c: string; k: string; total: string; errs: number | null; cand: string;
  }>(
    `SELECT h.id, h.name, h.hostname, h.kind, h.os_name, h.os_version, h.agent_version, h.last_seen_at, h.stale_alerted, h.disabled,
       count(f.id) FILTER (WHERE NOT f.kev AND f.severity='critical') AS c,
       count(f.id) FILTER (WHERE f.kev) AS k, count(f.id) AS total,
       (SELECT jsonb_array_length(errors) FROM reports r WHERE r.host_id=h.id ORDER BY received_at DESC LIMIT 1) AS errs,
       (SELECT count(*) FROM systems s WHERE s.host_id=h.id AND s.origin='auto' AND s.root<>'__os__') AS cand
     FROM hosts h LEFT JOIN findings f ON f.host_id=h.id AND f.status='open'
     GROUP BY h.id ORDER BY h.name`,
  );
  // registered projects per host (shown inline when a host is expanded)
  const projects = await q<{ id: number; host_id: string; name: string; root: string; exposure: string; criticality: string; ignored: boolean; stack: string; k: string; c: string; hi: string; total: string; pkgs: string }>(
    `SELECT s.id, s.host_id, s.name, s.root, s.exposure, s.criticality, s.ignored, s.stack,
       count(f.id) FILTER (WHERE f.kev) AS k, count(f.id) FILTER (WHERE NOT f.kev AND f.severity='critical') AS c,
       count(f.id) FILTER (WHERE NOT f.kev AND f.severity='high') AS hi, count(f.id) AS total,
       (SELECT count(*) FROM host_packages p WHERE p.host_id=s.host_id AND s.root = ANY(p.systems)) AS pkgs
     FROM systems s LEFT JOIN findings f ON f.host_id=s.host_id AND f.status='open' AND s.root = ANY(f.systems)
     WHERE s.origin='manual' AND s.root <> '__os__'
     GROUP BY s.id ORDER BY s.name`,
  );
  const projByHost = new Map<string, typeof projects>();
  for (const p of projects) projByHost.set(p.host_id, [...(projByHost.get(p.host_id) ?? []), p]);
  const dot = (h: typeof hosts[number]) => h.disabled ? 'bg-slate-400' : h.stale_alerted ? 'bg-orange-500' : 'bg-green-500';

  return (
    <>
      <Breadcrumbs items={[CRUMB.home, { label: '資産' }]} />
      <div className="flex flex-wrap items-center gap-2 text-sm">
        <h1 className="mr-auto text-xl font-semibold">資産（ホスト {hosts.length}台・登録プロジェクト {projects.length}）</h1>
        <form action={collectAllHosts}><button className="btn-ghost" title="全エージェントホストに収集を要求（接続中は即時）">全ホスト 今すぐ収集</button></form>
        <form action={rematchAllHosts}><button className="btn-ghost" title="取得済みインベントリで全ホストを再判定（ホストへ接続しません）">全ホスト 再照合</button></form>
        <Link className="btn-ghost" href="/enroll">エージェント型ホストを追加</Link>
        <Link className="btn-ghost" href="/hosts/pull/new">プル型ホストを追加（SSH）</Link>
      </div>
      <p className="text-sm text-muted">ホストを開くと、その配下の<b>監視中プロジェクト（登録済み）</b>が見られます。未登録の候補は各ホストの画面で承認して登録します。</p>
      {hosts.length === 0 ? (
        <Card><p className="text-sm text-muted">ホストはまだありません。<Link className="text-accent" href="/enroll">最初のホストを追加</Link>してください。</p></Card>
      ) : (
        <div className="space-y-2">
          {hosts.map((h) => {
            const projs = projByHost.get(h.id) ?? [];
            return (
              <details key={h.id} className={`rounded-lg border border-line bg-panel ${h.disabled ? 'opacity-60' : ''}`}>
                <summary className="flex cursor-pointer flex-wrap items-center gap-x-3 gap-y-1 px-3 py-3 text-sm [&::-webkit-details-marker]:hidden">
                  <span className="tri shrink-0 text-xs text-muted" aria-hidden="true">▶</span>
                  <span className={`inline-block h-2 w-2 shrink-0 rounded-full ${dot(h)}`} title={h.disabled ? '無効' : h.stale_alerted ? '報告停止' : '報告中'} />
                  <Link href={`/hosts/${h.id}`} className="font-medium text-accent">{h.name}</Link>
                  {h.kind === 'pull' && <span className="rounded bg-indigo-600 px-1.5 text-[11px] text-white">プル型</span>}
                  <span className="text-xs text-muted">{h.os_name} {h.os_version}</span>
                  <span className="rounded bg-bg px-1.5 text-[11px] text-muted">プロジェクト {projs.length}{Number(h.cand) ? ` ／候補 ${h.cand}` : ''}</span>
                  <span className={`text-xs ${h.stale_alerted ? 'text-orange-500' : 'text-muted'}`}>{h.disabled ? '無効' : `報告 ${ago(h.last_seen_at)}`}</span>
                  {Number(h.errs) ? <span className="text-xs text-orange-500" title="直近の収集エラー">!{h.errs}</span> : null}
                  <span className="ml-auto flex items-center gap-3">
                    <span className={Number(h.k) ? 'font-semibold text-red-600' : 'text-muted'}>KEV {h.k}</span>
                    <span className={Number(h.c) ? 'text-orange-600' : 'text-muted'}>緊急 {h.c}</span>
                  </span>
                </summary>
                <div className="border-t border-line py-2 pl-7 pr-3 text-sm">
                  <div className="mb-1 flex flex-wrap items-center gap-3">
                    {Number(h.cand) > 0 && <Link href={`/hosts/${h.id}`} className="text-xs text-accent">未登録の候補 {h.cand}件を登録 →</Link>}
                    <Link href={`/hosts/${h.id}`} className="ml-auto text-xs text-accent">ホストの詳細・設定 →</Link>
                  </div>
                  {projs.length === 0 ? (
                    <p className="border-l-2 border-line pl-3 text-xs text-muted">登録済みプロジェクトはありません。{Number(h.cand) > 0 ? <>「<Link href={`/hosts/${h.id}`} className="text-accent">未登録の候補 {h.cand}件</Link>」から登録してください。</> : 'このホストでプロジェクトは検出されていません。'}</p>
                  ) : (
                    <ul className="border-l-2 border-line">
                      {projs.map((p) => (
                        <li key={p.id} className="flex flex-col gap-1 py-1.5 pl-3 sm:flex-row sm:items-center sm:gap-2">
                          <span className="flex min-w-0 flex-wrap items-center gap-1.5">
                            <span className="text-muted" aria-hidden="true">└</span>
                            <Link href={`/systems/${p.id}`} className="font-medium text-accent">{p.name}</Link>
                            {p.exposure === 'public' && <span className="rounded bg-red-100 px-1.5 text-[11px] text-red-700 dark:bg-red-950 dark:text-red-200">{EXPOSURE.public}</span>}
                            {p.exposure !== 'public' && p.exposure !== 'unknown' && <span className="rounded bg-bg px-1.5 text-[11px] text-muted">{EXPOSURE[p.exposure]}</span>}
                            {p.criticality !== 'normal' && <span className="rounded bg-bg px-1.5 text-[11px] text-muted">{CRITICALITY[p.criticality]}</span>}
                            {p.stack && <span className="rounded bg-bg px-1.5 text-[11px] text-muted">{p.stack}</span>}
                            {p.ignored && <span className="rounded bg-slate-500 px-1.5 text-[11px] text-white">除外中</span>}
                          </span>
                          <span className="ml-auto flex shrink-0 items-center gap-3 pl-5 text-xs sm:pl-0">
                            <span className="text-muted">pkg {p.pkgs}</span>
                            <span className={Number(p.k) ? 'font-semibold text-red-600' : 'text-muted'}>KEV {p.k}</span>
                            <span className={Number(p.c) ? 'text-orange-600' : 'text-muted'}>緊急 {p.c}</span>
                            <span className={Number(p.hi) ? 'text-yellow-600' : 'text-muted'}>高 {p.hi}</span>
                            <Link href={`/findings?host=${p.host_id}&system=${encodeURIComponent(p.root)}&all=1`} className="text-muted underline">他 {Number(p.total) - Number(p.k) - Number(p.c) - Number(p.hi)}</Link>
                          </span>
                        </li>
                      ))}
                    </ul>
                  )}
                </div>
              </details>
            );
          })}
        </div>
      )}
    </>
  );
}
