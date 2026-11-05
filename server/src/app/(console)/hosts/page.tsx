import { Breadcrumbs, CRUMB } from '@/components/Breadcrumbs';
import Link from 'next/link';
import { Masked } from '@/components/Mask';
import { Card, ago } from '@/components/ui';
import { CRITICALITY, EXPOSURE } from '@/lib/systemmeta';
import { q } from '@/lib/db';
import { FleetOps } from '@/components/FleetOps';
import { TreeState } from '@/components/TreeState';
import { taskKey } from '@/lib/tasks';
import { ConfirmCollect } from '@/components/ConfirmCollect';

export default async function HostsPage() {
  const hosts = await q<{
    id: string; name: string; hostname: string; kind: string; os_name: string; os_version: string; agent_version: string;
    last_seen_at: Date | null; ws_seen_at: Date | null; stale_alerted: boolean; disabled: boolean; c: string; k: string; total: string; errs: number | null; cand: string;
  }>(
    `SELECT h.id, h.name, h.hostname, h.kind, h.os_name, h.os_version, h.agent_version, h.last_seen_at, h.ws_seen_at, h.stale_alerted, h.disabled,
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
  // OS (host-wide) units
  const osRows = await q<{ host_id: string; sid: number | null; k: string; c: string; hi: string }>(
    `SELECT f.host_id, (SELECT id FROM systems s WHERE s.host_id=f.host_id AND s.root='__os__') AS sid,
       count(*) FILTER (WHERE kev) AS k, count(*) FILTER (WHERE NOT kev AND severity='critical') AS c,
       count(*) FILTER (WHERE NOT kev AND severity='high') AS hi
     FROM findings f WHERE status='open' AND '__os__' = ANY(systems) GROUP BY f.host_id`);
  const osByHost = new Map(osRows.map((r) => [r.host_id, r]));
  // shared runtime envs (conda/venv) used by registered projects — each a remediation unit
  const envs = await q<{ id: number; host_id: string; name: string; root: string; k: string; c: string; hi: string; total: string }>(
    `SELECT s.id, s.host_id, s.name, s.root,
       count(f.id) FILTER (WHERE f.kev) AS k, count(f.id) FILTER (WHERE NOT f.kev AND f.severity='critical') AS c,
       count(f.id) FILTER (WHERE NOT f.kev AND f.severity='high') AS hi, count(f.id) AS total
     FROM systems s
     JOIN (SELECT DISTINCT host_id, runtime_root FROM host_services WHERE runtime_root IS NOT NULL) rt ON rt.host_id=s.host_id AND rt.runtime_root=s.root
     LEFT JOIN findings f ON f.host_id=s.host_id AND s.root = ANY(f.systems) AND f.status='open'
     WHERE s.root <> '__os__' GROUP BY s.id ORDER BY s.name`);
  const envByHost = new Map<string, typeof envs>();
  for (const e of envs) envByHost.set(e.host_id, [...(envByHost.get(e.host_id) ?? []), e]);
  const dot = (h: typeof hosts[number]) => h.disabled ? 'bg-slate-400' : h.stale_alerted ? 'bg-orange-500' : 'bg-green-500';

  return (
    <>
      <Breadcrumbs items={[CRUMB.home, { label: '資産' }]} />
      <div className="flex flex-wrap items-center gap-2 text-sm">
        <h1 className="mr-auto text-xl font-semibold">資産（ホスト {hosts.length}台・登録プロジェクト {projects.length}）</h1>
        <FleetOps />
        <Link className="btn-ghost" href="/enroll">エージェント型ホストを追加</Link>
        <Link className="btn-ghost" href="/hosts/pull/new">プル型ホストを追加（SSH）</Link>
      </div>
      <p className="text-sm text-muted">ホストを開くと、その配下の<b>監視中プロジェクト（登録済み）</b>が見られます。未登録の候補は各ホストの画面で承認して登録します。</p>
      {hosts.length === 0 ? (
        <Card><p className="text-sm text-muted">ホストはまだありません。<Link className="text-accent" href="/enroll">最初のホストを追加</Link>してください。</p></Card>
      ) : (
        <div className="space-y-2">
          <TreeState />
          {hosts.map((h) => {
            const projs = projByHost.get(h.id) ?? [];
            const os = osByHost.get(h.id);
            const envList = envByHost.get(h.id) ?? [];
            return (
              <details key={h.id} data-host={h.id} className={`rounded-lg border border-line bg-panel ${h.disabled ? 'opacity-60' : ''}`}>
                <summary className="flex cursor-pointer flex-wrap items-center gap-x-3 gap-y-1 px-3 py-3 text-sm [&::-webkit-details-marker]:hidden">
                  <span className="tri shrink-0 text-xs text-muted" aria-hidden="true">▶</span>
                  <span className={`inline-block h-2 w-2 shrink-0 rounded-full ${dot(h)}`} title={h.disabled ? '無効' : h.stale_alerted ? '報告停止' : '報告中'} />
                  <Link href={`/hosts/${h.id}`} className="font-medium text-accent"><Masked kind="host">{h.name}</Masked></Link>
                  {h.kind === 'pull' && <span className="rounded bg-indigo-600 px-1.5 text-[11px] text-white">プル型</span>}
                  <span className="text-xs text-muted">{h.os_name} {h.os_version}</span>
                  <span className="rounded bg-bg px-1.5 text-[11px] text-muted">プロジェクト {projs.length}{Number(h.cand) ? ` ／候補 ${h.cand}` : ''}</span>
                  <span className={`text-xs ${h.stale_alerted ? 'text-orange-500' : 'text-muted'}`}>{h.disabled ? '無効' : `報告 ${ago(h.last_seen_at)}`}</span>
                  {Number(h.errs) ? <span className="text-xs text-orange-500" title="直近の収集エラー">!{h.errs}</span> : null}
                  <span className="ml-auto flex items-center gap-3">
                    <span className={Number(h.k) ? 'font-semibold text-red-600' : 'text-muted'}>KEV {h.k}</span>
                    <span className={Number(h.c) ? 'font-bold text-red-600' : 'text-muted'}>緊急 {h.c}</span>
                    {!h.disabled && <ConfirmCollect hostId={h.id} pull={h.kind === 'pull'} online={!!h.ws_seen_at && Date.now() - new Date(h.ws_seen_at).getTime() < 75_000} lastSeenAt={h.last_seen_at ? new Date(h.last_seen_at).toISOString() : null} compact />}
                  </span>
                </summary>
                <div className="border-t border-line py-2 pl-7 pr-3 text-sm">
                  {/* host-wide units: OS + shared runtime envs, each a remediation target */}
                  {(os && (Number(os.k) + Number(os.c) > 0)) && (
                    <div className="mb-1 flex flex-wrap items-center gap-2 border-l-2 border-red-300 pl-3 py-1">
                      <Link href={os.sid ? `/systems/${os.sid}` : `/actions/${taskKey(h.id, '__os__')}`} className="font-medium text-accent">OS（ホスト全体）</Link>
                      <span className="text-xs text-muted">kernel・glibc・openssl 等</span>
                      <span className="ml-auto flex items-center gap-3 text-xs">
                        <span className={Number(os.k) ? 'font-semibold text-red-600' : 'text-muted'}>KEV {os.k}</span>
                        <span className={Number(os.c) ? 'font-bold text-red-600' : 'text-muted'}>緊急 {os.c}</span>
                      </span>
                    </div>
                  )}
                  {envList.filter((e) => Number(e.k) + Number(e.c) + Number(e.hi) > 0).map((e) => (
                    <div key={e.id} className="mb-1 flex flex-wrap items-center gap-2 border-l-2 border-indigo-300 pl-3 py-1">
                      <Link href={`/systems/${e.id}`} className="font-medium text-accent">実行環境：<Masked kind="system">{e.name}</Masked></Link>
                      <span className="text-xs text-muted">共有ランタイム（複数プロジェクトで使用）</span>
                      <span className="ml-auto flex items-center gap-3 text-xs">
                        <span className={Number(e.k) ? 'font-semibold text-red-600' : 'text-muted'}>KEV {e.k}</span>
                        <span className={Number(e.c) ? 'font-bold text-red-600' : 'text-muted'}>緊急 {e.c}</span>
                        <span className={Number(e.hi) ? 'text-yellow-600' : 'text-muted'}>高 {e.hi}</span>
                      </span>
                    </div>
                  ))}
                  {projs.length === 0 ? (
                    <p className="border-l-2 border-line pl-3 text-xs text-muted">登録済みプロジェクトはありません。{Number(h.cand) > 0 ? <>「<Link href={`/hosts/${h.id}`} className="text-accent">未登録の候補 {h.cand}件</Link>」から登録してください。</> : 'このホストでプロジェクトは検出されていません。'}</p>
                  ) : (
                    <ul className="border-l-2 border-line">
                      {projs.map((p) => (
                        <li key={p.id} className="flex flex-col gap-1 py-1.5 pl-3 sm:flex-row sm:items-center sm:gap-2">
                          <span className="flex min-w-0 flex-wrap items-center gap-1.5">
                            <span className="text-muted" aria-hidden="true">└</span>
                            <Link href={`/systems/${p.id}`} className="font-medium text-accent"><Masked kind="system">{p.name}</Masked></Link>
                            {p.exposure === 'public' && <span className="rounded bg-red-100 px-1.5 text-[11px] text-red-700 dark:bg-red-950 dark:text-red-200">{EXPOSURE.public}</span>}
                            {p.exposure !== 'public' && p.exposure !== 'unknown' && <span className="rounded bg-bg px-1.5 text-[11px] text-muted">{EXPOSURE[p.exposure]}</span>}
                            {p.criticality !== 'normal' && <span className="rounded bg-bg px-1.5 text-[11px] text-muted">{CRITICALITY[p.criticality]}</span>}
                            {p.stack && <span className="rounded bg-bg px-1.5 text-[11px] text-muted">{p.stack}</span>}
                            {p.ignored && <span className="rounded bg-slate-500 px-1.5 text-[11px] text-white">除外中</span>}
                          </span>
                          <span className="ml-auto flex shrink-0 items-center gap-3 pl-5 text-xs sm:pl-0">
                            <span className="text-muted">pkg {p.pkgs}</span>
                            <span className={Number(p.k) ? 'font-semibold text-red-600' : 'text-muted'}>KEV {p.k}</span>
                            <span className={Number(p.c) ? 'font-bold text-red-600' : 'text-muted'}>緊急 {p.c}</span>
                            <span className={Number(p.hi) ? 'text-yellow-600' : 'text-muted'}>高 {p.hi}</span>
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
