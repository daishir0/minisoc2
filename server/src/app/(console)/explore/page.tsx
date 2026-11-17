import { Breadcrumbs, CRUMB } from '@/components/Breadcrumbs';
import Link from 'next/link';
import { CveSearch } from '@/components/CveSearch';
import { ExploreTabs } from '@/components/ExploreTabs';
import { Card, ago } from '@/components/ui';
import { q } from '@/lib/db';

export default async function ExplorePage() {
  // Each looked-up CVE = a CVE the user cares about. Resolve its current state across hosts so the chip
  // can say at a glance whether it is cleared: open = findings still open, total = findings ever seen,
  // summary = the CVE description (shown on hover for anything not yet resolved).
  const recent = await q<{ cve: string; fetched_at: Date; open_cnt: number; total_cnt: number; summary: string | null }>(
    `SELECT l.cve, l.fetched_at,
       (SELECT count(*) FROM findings f WHERE f.status='open'
          AND (f.vuln_id = l.cve OR EXISTS (SELECT 1 FROM vulns v WHERE v.id = f.vuln_id AND l.cve = ANY(v.aliases))))::int AS open_cnt,
       (SELECT count(*) FROM findings f
          WHERE (f.vuln_id = l.cve OR EXISTS (SELECT 1 FROM vulns v WHERE v.id = f.vuln_id AND l.cve = ANY(v.aliases))))::int AS total_cnt,
       (SELECT summary FROM vulns v WHERE v.id = l.cve OR l.cve = ANY(v.aliases) LIMIT 1) AS summary
     FROM cve_lookups l ORDER BY l.fetched_at DESC LIMIT 8`,
  );
  return (
    <>
      <Breadcrumbs items={[CRUMB.home, { label: "検知" }]} />
      <ExploreTabs />
      <Card title="CVE照会：この CVE はうちに関係ある？">
        <p className="mb-3 text-sm text-muted">記事やニュースで見かけた CVE を入れると、ホストごとに「影響あり／なし／判定できない」を根拠つきで返します。上部の検索窓からも照会できます。</p>
        <CveSearch autoFocus />
        {recent.length > 0 && (
          <>
            <p className="mt-4 mb-2 text-xs text-muted">最近照会した（関心のある）CVE。<span className="text-green-600">緑＝解消済</span>／<span className="text-red-600">赤＝未解消</span>／灰＝未検出。未解消・未検出はマウスオーバーで概要が出ます。</p>
            <div className="flex flex-wrap gap-2 text-sm">
              {recent.map((r) => {
                const open = Number(r.open_cnt), total = Number(r.total_cnt);
                const resolved = open === 0 && total > 0;
                const sm = (r.summary ?? '').replace(/\s+/g, ' ').trim();
                const cls = resolved
                  ? 'border-green-500 bg-green-50 text-green-700 dark:bg-green-950 dark:text-green-200'
                  : open > 0
                  ? 'border-red-400 bg-red-50 text-red-700 dark:bg-red-950 dark:text-red-200'
                  : 'border-line text-muted';
                const status = resolved ? '解消済' : open > 0 ? `未解消 ${open}` : '未検出';
                const tip = (resolved
                  ? `解消済（過去に${total}件検出・現在0件）`
                  : open > 0
                  ? `未解消：影響あり ${open}件${sm ? ` — ${sm}` : ''}`
                  : `未検出（このCVEに一致する脆弱性は検出されていません）${sm ? ` — ${sm}` : ''}`) + `／照会 ${ago(r.fetched_at)}`;
                return (
                  <Link key={r.cve} href={`/cve/${r.cve}`} title={tip} className={`btn-ghost border font-mono ${cls}`}>
                    <span aria-hidden="true">{resolved ? '✅ ' : open > 0 ? '⚠ ' : ''}</span>{r.cve}
                    <span className="ml-2 text-xs opacity-80">{status}</span>
                  </Link>
                );
              })}
            </div>
          </>
        )}
      </Card>
    </>
  );
}
