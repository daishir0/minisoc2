import Link from 'next/link';
import { CveSearch } from '@/components/CveSearch';
import { ExploreTabs } from '@/components/ExploreTabs';
import { Card, Sev, ago } from '@/components/ui';
import { q } from '@/lib/db';
import { watchCve } from '../actions';

export default async function ExplorePage() {
  // Each looked-up CVE = a CVE the user cared enough to check. Resolve its current state across hosts and
  // pull a one-line description + severity + whether it is already on watch, so the list reads at a glance.
  // Ordered newest-first (time order), the way the user scans "what did I look at recently".
  const recent = await q<{ cve: string; fetched_at: Date; open_cnt: number; total_cnt: number; summary: string | null; severity: string | null; watch_status: string | null }>(
    `SELECT l.cve, l.fetched_at,
       (SELECT count(*) FROM findings f WHERE f.status='open'
          AND (f.vuln_id = l.cve OR EXISTS (SELECT 1 FROM vulns v WHERE v.id = f.vuln_id AND l.cve = ANY(v.aliases))))::int AS open_cnt,
       (SELECT count(*) FROM findings f
          WHERE (f.vuln_id = l.cve OR EXISTS (SELECT 1 FROM vulns v WHERE v.id = f.vuln_id AND l.cve = ANY(v.aliases))))::int AS total_cnt,
       (SELECT summary FROM vulns v WHERE v.id = l.cve OR l.cve = ANY(v.aliases) LIMIT 1) AS summary,
       (SELECT severity FROM vulns v WHERE v.id = l.cve OR l.cve = ANY(v.aliases) LIMIT 1) AS severity,
       (SELECT status FROM watch_cves w WHERE w.cve = l.cve) AS watch_status
     FROM cve_lookups l ORDER BY l.fetched_at DESC LIMIT 20`,
  );
  return (
    <>
      <ExploreTabs />
      <Card title="CVE照会：この CVE はうちに関係ある？">
        <p className="mb-3 text-sm text-muted">記事やニュースで見かけた CVE を入れると、ホストごとに「影響あり／なし／判定できない」を根拠つきで返します。<b>照会</b>は調べるだけ（記録は残りますが通知はしません）。継続して追いたいものは「監視」に入れてください。</p>
        <CveSearch autoFocus />
        {recent.length > 0 && (
          <>
            <p className="mt-4 mb-2 text-xs text-muted">最近照会した（関心のある）CVE・新しい順。<span className="text-red-600">未解消</span>／<span className="text-green-600">解消済</span>／灰＝未検出。</p>
            <ul className="divide-y divide-line">
              {recent.map((r) => {
                const open = Number(r.open_cnt), total = Number(r.total_cnt);
                const resolved = open === 0 && total > 0;
                const sm = (r.summary ?? '').replace(/\s+/g, ' ').trim();
                const state = open > 0 ? `未解消 ${open}` : resolved ? '解消済' : '未検出';
                const stateCls = open > 0 ? 'text-red-600' : resolved ? 'text-green-600' : 'text-muted';
                const ws = r.watch_status;
                return (
                  <li key={r.cve} className="flex flex-wrap items-center gap-x-3 gap-y-1 py-2 sm:flex-nowrap">
                    <span className="w-14 shrink-0">{r.severity && r.severity !== 'unknown' ? <Sev s={r.severity} /> : <span className="text-xs text-muted">—</span>}</span>
                    <div className="min-w-0 flex-1">
                      <div className="flex items-center gap-2">
                        <Link href={`/cve/${r.cve}`} className="font-mono text-sm text-accent hover:underline">{r.cve}</Link>
                        <span className={`text-xs ${stateCls}`}>{state}</span>
                      </div>
                      <div className="line-clamp-1 text-xs text-muted" title={sm}>{sm || '（概要情報なし）'}</div>
                    </div>
                    <span className="whitespace-nowrap text-xs text-muted">照会 {ago(r.fetched_at)}</span>
                    {ws === 'watching' ? <span className="whitespace-nowrap text-xs text-accent">監視中</span>
                      : ws === 'resolved' ? <span className="whitespace-nowrap text-xs text-green-600">監視（解決）</span>
                      : <form action={watchCve}><input type="hidden" name="cve" value={r.cve} /><button className="whitespace-nowrap rounded-full border border-line px-2 py-0.5 text-xs hover:border-accent">監視に追加</button></form>}
                  </li>
                );
              })}
            </ul>
          </>
        )}
      </Card>
    </>
  );
}
