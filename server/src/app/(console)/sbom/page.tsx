import { ExploreTabs } from '@/components/ExploreTabs';
import { Card } from '@/components/ui';
import { SbomBrowser } from '@/components/SbomBrowser';
import { q } from '@/lib/db';

// 検知 ▸ SBOM: fleet-wide component inventory. Search + filter (host / ecosystem / layer / license / vuln)
// across every host's packages, with a reverse-lookup of where each component is used. ?license=copyleft
// reproduces the old /licenses view.
export const dynamic = 'force-dynamic';

export default async function SbomPage({ searchParams }: { searchParams: Promise<Record<string, string | undefined>> }) {
  const sp = await searchParams;
  const hosts = await q<{ id: string; name: string }>('SELECT id, name FROM hosts WHERE NOT disabled ORDER BY name');
  const ecos = (await q<{ ecosystem: string }>('SELECT ecosystem, count(*) n FROM host_packages GROUP BY ecosystem ORDER BY n DESC')).map((r) => r.ecosystem);
  const initialLicense = sp.license === 'copyleft' ? 'copyleft' : '';
  return (
    <>
      <ExploreTabs />
      <Card title="SBOM：横断 部品インベントリ">
        <p className="mb-3 text-xs text-muted">
          全ホストの部品を横断検索。「どの部品が・どこに・どんなライセンス/脆弱性で入っているか」を調べられます（例：特定ライブラリの影響範囲、コピーレフトの所在）。
          各プロジェクト単位の部品表は各システム画面の「SBOM：部品一覧」にあります。
        </p>
        <SbomBrowser hosts={hosts} ecos={ecos} initialLicense={initialLicense} />
      </Card>
    </>
  );
}
