import Link from 'next/link';
import { AssetTabs } from '@/components/AssetTabs';
import { Card } from '@/components/ui';
import { q } from '@/lib/db';
import { CRITICALITY, EXPOSURE, STACK_KEYS, detectStack } from '@/lib/systemmeta';
import { systemAction } from '../actions';

export default async function SystemsPage({ searchParams }: { searchParams: Promise<{ ignored?: string }> }) {
  const sp = await searchParams;
  const showIgnored = sp.ignored === '1';
  const rows = await q<{
    id: number; host_id: string; host: string; root: string; name: string; ignored: boolean; origin: string; exposure: string; criticality: string;
    url: string; stack: string; ecos: string[] | null; markers: string[] | null; pkgs: string; exn: string; c: string; h: string; m: string; k: string; total: string;
  }>(
    `SELECT s.id, s.host_id, h.name AS host, s.root, s.name, s.ignored, s.origin, s.exposure, s.criticality, s.url, s.stack,
       (SELECT array_agg(DISTINCT p.ecosystem) FROM host_packages p WHERE p.host_id=s.host_id AND s.root = ANY(p.systems)) AS ecos,
       (SELECT array_agg(DISTINCT p.ecosystem || ':' || p.name) FROM host_packages p WHERE p.host_id=s.host_id AND s.root = ANY(p.systems)
          AND p.ecosystem || ':' || p.name = ANY($2::text[])) AS markers,
       (SELECT count(*) FROM host_packages p WHERE p.host_id=s.host_id AND s.root = ANY(p.systems)) AS pkgs,
       (SELECT count(*) FROM host_packages_excluded x WHERE x.host_id=s.host_id AND x.system_root=s.root) AS exn,
       count(f.id) FILTER (WHERE NOT f.kev AND f.severity='critical') AS c, count(f.id) FILTER (WHERE f.severity='high') AS h,
       count(f.id) FILTER (WHERE f.severity='medium') AS m, count(f.id) FILTER (WHERE f.kev) AS k, count(f.id) AS total
     FROM systems s JOIN hosts h ON h.id=s.host_id
     LEFT JOIN findings f ON f.host_id=s.host_id AND f.status='open' AND s.root = ANY(f.systems)
     WHERE s.ignored = $1
     GROUP BY s.id, h.name
     ORDER BY h.name, (s.root = '__os__') DESC, CASE s.exposure WHEN 'public' THEN 0 WHEN 'internal' THEN 1 WHEN 'unknown' THEN 2 ELSE 3 END,
       count(f.id) FILTER (WHERE f.kev) DESC, count(f.id) FILTER (WHERE f.severity='critical') DESC, count(f.id) FILTER (WHERE f.severity='high') DESC, s.name`,
    [showIgnored, STACK_KEYS],
  );
  const byHost = new Map<string, typeof rows>();
  for (const r of rows) byHost.set(r.host, [...(byHost.get(r.host) ?? []), r]);
  const badge = 'rounded bg-bg px-1.5 py-0.5 text-[11px] text-muted';

  return (
    <>
      <AssetTabs />
      <div className="flex flex-wrap items-center gap-3">
        <h1 className="text-xl font-semibold">システム</h1>
        <div className="flex gap-3 text-sm">
          <Link href="/systems" className={showIgnored ? 'text-muted' : 'font-semibold'}>監視中</Link>
          <Link href="/systems?ignored=1" className={showIgnored ? 'font-semibold' : 'text-muted'}>除外中</Link>
        </div>
        <Link href="/systems/new" className="btn-ghost ml-auto">システムを登録</Link>
      </div>
      <p className="text-sm text-muted">
        ホスト上の開発システム（プロジェクト）と、共有の Python 環境です。通常はエージェントが lockfile・venv の場所から自動で検出します。
        公開区分や重要度、場所の固定は、各システムの画面で設定できます。「除外」したシステムの脆弱性は数えず、通知もしません。
      </p>
      {rows.length === 0 && <Card><p className="text-sm text-muted">{showIgnored ? '除外中のシステムはありません。' : 'まだシステムがありません（エージェントの次回報告で作られます）。'}</p></Card>}
      {[...byHost.entries()].map(([host, list]) => (
        <Card key={host} title={`${host}（${list.length}システム）`}>
          <ul className="divide-y divide-line">
            {list.map((s) => {
              const stack = s.stack || detectStack(s.markers ?? [], s.ecos ?? []);
              return (
                <li key={s.id} className="flex flex-col gap-2 py-3 sm:flex-row sm:items-center">
                  <div className="min-w-0 flex-1">
                    <div className="flex flex-wrap items-center gap-1.5">
                      <Link href={`/systems/${s.id}`} className="font-medium text-accent">{s.name}</Link>
                      {s.exposure === 'public' && <span className="rounded bg-red-100 px-1.5 py-0.5 text-[11px] text-red-700 dark:bg-red-950 dark:text-red-200">{EXPOSURE.public}</span>}
                      {s.exposure !== 'public' && s.exposure !== 'unknown' && <span className={badge}>{EXPOSURE[s.exposure]}</span>}
                      {s.criticality !== 'normal' && <span className={badge}>{CRITICALITY[s.criticality]}</span>}
                      {stack && <span className={badge}>{stack}</span>}
                      {s.origin === 'manual' && <span className={badge}>手動登録</span>}
                      {Number(s.exn) > 0 && <span className={badge}>除外中 {s.exn}</span>}
                    </div>
                    <div className="break-all font-mono text-xs text-muted">{s.root === '__os__' ? 'OSのパッケージマネージャ' : s.root}</div>
                    <div className="mt-1 flex flex-wrap gap-3 text-sm">
                      <span className={Number(s.k) ? 'font-semibold text-red-600' : ''}>KEV {s.k}</span>
                      <span className={Number(s.c) ? 'text-orange-600' : ''}>緊急 {s.c}</span>
                      <Link href={`/findings?host=${s.host_id}&system=${encodeURIComponent(s.root)}&all=1`} className="text-muted underline">その他 {Number(s.total) - Number(s.k) - Number(s.c)}</Link>
                      <span className="text-muted">パッケージ {s.pkgs}</span>
                    </div>
                  </div>
                  <div className="flex flex-wrap gap-2">
                    <Link href={`/systems/${s.id}`} className="btn-ghost">編集</Link>
                    {s.root !== '__os__' && (
                      <form action={systemAction}>
                        <input type="hidden" name="id" value={s.id} /><input type="hidden" name="op" value={s.ignored ? 'watch' : 'ignore'} />
                        <button className="btn-ghost">{s.ignored ? '監視に戻す' : '除外する'}</button>
                      </form>
                    )}
                  </div>
                </li>
              );
            })}
          </ul>
        </Card>
      ))}
    </>
  );
}
