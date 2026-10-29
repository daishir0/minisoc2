import { Breadcrumbs, CRUMB } from '@/components/Breadcrumbs';
import Link from 'next/link';
import { CveSearch } from '@/components/CveSearch';
import { ExploreTabs } from '@/components/ExploreTabs';
import { Card, ago } from '@/components/ui';
import { q } from '@/lib/db';

export default async function ExplorePage() {
  const recent = await q<{ cve: string; fetched_at: Date }>('SELECT cve, fetched_at FROM cve_lookups ORDER BY fetched_at DESC LIMIT 8');
  return (
    <>
      <Breadcrumbs items={[CRUMB.home, { label: "検知" }]} />
      <ExploreTabs />
      <Card title="CVE照会：この CVE はうちに関係ある？">
        <p className="mb-3 text-sm text-muted">記事やニュースで見かけた CVE を入れると、ホストごとに「影響あり／なし／判定できない」を根拠つきで返します。上部の検索窓からも照会できます。</p>
        <CveSearch autoFocus />
        {recent.length > 0 && (
          <div className="mt-4 flex flex-wrap gap-2 text-sm">
            {recent.map((r) => <Link key={r.cve} href={`/cve/${r.cve}`} className="btn-ghost font-mono">{r.cve}<span className="ml-2 text-xs text-muted">{ago(r.fetched_at)}</span></Link>)}
          </div>
        )}
      </Card>
    </>
  );
}
