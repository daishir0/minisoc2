import Link from 'next/link';
import { Masked } from '@/components/Mask';
import { ExploreTabs } from '@/components/ExploreTabs';
import { Card } from '@/components/ui';
import { q } from '@/lib/db';
import { classifyLicense } from '@/lib/licenses';

// 検知 ▸ ライセンス: reverse lookup of notable (copyleft) OSS licenses — which PROJECT (system) pulls them
// in. App ecosystems only (npm / PyPI / Packagist); OS packages are out of scope. The SQL pre-filters to
// copyleft-ish strings so the result stays small; the exact class is decided in classifyLicense().
export const dynamic = 'force-dynamic';

export default async function LicensesPage() {
  const rows = await q<{ ecosystem: string; name: string; version: string; license: string; host: string; root: string; system_name: string | null; system_id: number | null }>(
    `SELECT hp.ecosystem, hp.name, hp.version, hp.license, h.name AS host,
       sr AS root, s.name AS system_name, s.id AS system_id
     FROM host_packages hp
       JOIN hosts h ON h.id=hp.host_id
       CROSS JOIN LATERAL unnest(hp.systems) AS sr
       LEFT JOIN systems s ON s.host_id=hp.host_id AND s.root=sr
     WHERE hp.ecosystem IN ('npm','PyPI','Packagist') AND hp.license IS NOT NULL AND hp.license <> ''
       AND hp.license ~* '(GPL|AGPL|LGPL|MPL|EPL|CDDL|EUPL|OSL)'
       AND sr <> '__os__'
     ORDER BY hp.name`,
  );

  // Aggregate: one row per (license, package) with the set of projects that use it.
  type Proj = { label: string; href: string };
  const agg = new Map<string, { license: string; cls: 'strong' | 'weak'; pkg: string; projects: Map<string, Proj> }>();
  for (const r of rows) {
    const c = classifyLicense(r.license);
    if (c !== 'strong' && c !== 'weak') continue;
    const key = `${r.license}|${r.ecosystem}:${r.name}`;
    const e = agg.get(key) ?? { license: r.license, cls: c, pkg: `${r.name} ${r.version}`, projects: new Map<string, Proj>() };
    const label = r.system_name ?? (r.root === '__os__' ? 'OS' : r.root.split('/').pop() ?? r.root);
    const href = r.system_id ? `/systems/${r.system_id}` : `/hosts`;
    e.projects.set(`${r.host}|${label}`, { label, href });
    agg.set(key, e);
  }
  const items = [...agg.values()].sort((a, b) => (a.cls === b.cls ? a.pkg.localeCompare(b.pkg) : a.cls === 'strong' ? -1 : 1));
  const strongN = items.filter((i) => i.cls === 'strong').length;
  const weakN = items.filter((i) => i.cls === 'weak').length;

  return (
    <>
      <ExploreTabs />
      <Card title={`ライセンス：要注意の逆引き${items.length ? `（強 ${strongN}・弱 ${weakN}）` : ''}`}>
        <p className="mb-3 text-xs text-muted">
          コピーレフト系ライセンス（GPL/AGPL＝強、LGPL/MPL等＝弱）を使っている<b>プロジェクト（出荷・公開の単位）</b>を逆引きします。
          アプリ依存（npm / PyPI / Packagist）が対象で、OSパッケージは含みません。各プロジェクトのライセンス構成はシステム画面の「ライセンス構成」で確認できます。
        </p>
        {items.length === 0 ? (
          <p className="rounded border border-line bg-bg p-3 text-sm text-green-600">要注意ライセンス（コピーレフト）は検出されていません。<span className="text-muted">（ライセンスは収集・照会が進むと反映されます）</span></p>
        ) : (
          <div className="overflow-x-auto">
            <table className="tbl text-sm"><thead><tr><th>区分</th><th>ライセンス</th><th>パッケージ</th><th>使っているプロジェクト</th></tr></thead><tbody>
              {items.map((it, i) => (
                <tr key={i}>
                  <td>{it.cls === 'strong'
                    ? <span className="rounded bg-red-100 px-1.5 py-0.5 text-[10px] text-red-700 dark:bg-red-950 dark:text-red-200">強</span>
                    : <span className="rounded bg-amber-100 px-1.5 py-0.5 text-[10px] text-amber-800 dark:bg-amber-950 dark:text-amber-200">弱</span>}</td>
                  <td className="whitespace-nowrap font-mono text-xs">{it.license}</td>
                  <td className="break-all font-mono text-xs">{it.pkg}</td>
                  <td className="text-xs">
                    {[...it.projects.values()].map((p, j) => (
                      <span key={j}>{j > 0 && '、'}<Link className="text-accent" href={p.href}><Masked kind="system">{p.label}</Masked></Link></span>
                    ))}
                  </td>
                </tr>
              ))}
            </tbody></table>
          </div>
        )}
      </Card>
    </>
  );
}
