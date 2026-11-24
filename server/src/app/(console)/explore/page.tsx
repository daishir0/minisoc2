import Link from 'next/link';
import { CveSearch } from '@/components/CveSearch';
import { ExploreTabs } from '@/components/ExploreTabs';
import { Card, ago } from '@/components/ui';
import { q } from '@/lib/db';
import { watchCve } from '../actions';

const SEV: Record<string, [string, string]> = {
  critical: ['緊急', 'bg-red-600 text-white'],
  high: ['高', 'bg-orange-500 text-white'],
  medium: ['中', 'bg-amber-400 text-black'],
  low: ['低', 'bg-slate-300 text-slate-800 dark:bg-slate-700 dark:text-slate-100'],
};

export default async function ExplorePage() {
  // Each looked-up CVE = a CVE the user cared enough to check. Severity, score and the one-line description
  // come from the lookup cache (cve_lookups.data.nvd, then the first GHSA advisory, then the vulns table),
  // so the list is informative even for CVEs we have never detected on a host. Newest-first (time order).
  const recent = await q<{ cve: string; fetched_at: Date; open_cnt: number; total_cnt: number; summary: string | null; severity: string | null; score: string | null; watch_status: string | null }>(
    `SELECT l.cve, l.fetched_at,
       (SELECT count(*) FROM findings f WHERE f.status='open'
          AND (f.vuln_id = l.cve OR EXISTS (SELECT 1 FROM vulns v WHERE v.id = f.vuln_id AND l.cve = ANY(v.aliases))))::int AS open_cnt,
       (SELECT count(*) FROM findings f
          WHERE (f.vuln_id = l.cve OR EXISTS (SELECT 1 FROM vulns v WHERE v.id = f.vuln_id AND l.cve = ANY(v.aliases))))::int AS total_cnt,
       coalesce(nullif(l.data->'nvd'->>'description',''), nullif(l.data->'ghsa'->0->>'summary',''),
                (SELECT summary FROM vulns v WHERE v.id = l.cve OR l.cve = ANY(v.aliases) LIMIT 1)) AS summary,
       coalesce(lower(nullif(l.data->'nvd'->>'severity','')), lower(nullif(l.data->'ghsa'->0->>'severity','')),
                (SELECT severity FROM vulns v WHERE v.id = l.cve OR l.cve = ANY(v.aliases) LIMIT 1)) AS severity,
       l.data->'nvd'->>'score' AS score,
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
            <p className="mt-4 mb-1 text-xs text-muted">最近照会した（関心のある）CVE・新しい順。<span className="text-red-600">未解消</span>／<span className="text-green-600">解消済</span>／灰＝未検出。</p>
            <ul className="divide-y divide-line">
              {recent.map((r) => {
                const open = Number(r.open_cnt), total = Number(r.total_cnt);
                const resolved = open === 0 && total > 0;
                const sm = (r.summary ?? '').replace(/\s+/g, ' ').trim();
                const sev = r.severity && SEV[r.severity] ? r.severity : null;
                const [sevLabel, sevCls] = sev ? SEV[sev] : ['', ''];
                const state = open > 0 ? `未解消 ${open}` : resolved ? '解消済' : '未検出';
                const stateCls = open > 0 ? 'text-red-600' : resolved ? 'text-green-600' : 'text-muted';
                const ws = r.watch_status;
                return (
                  <li key={r.cve} className="flex items-start gap-3 py-2.5">
                    <span className="w-16 shrink-0 pt-0.5">
                      {sev ? <span className={`inline-block rounded px-1.5 py-0.5 text-[11px] font-bold ${sevCls}`}>{sevLabel}{r.score ? ` ${r.score}` : ''}</span>
                        : <span className="text-xs text-muted">—</span>}
                    </span>
                    <div className="min-w-0 flex-1">
                      <div className="flex flex-wrap items-center gap-x-2 gap-y-0.5">
                        <Link href={`/cve/${r.cve}`} className="font-mono text-sm text-accent hover:underline">{r.cve}</Link>
                        <span className={`text-xs ${stateCls}`}>{state}</span>
                      </div>
                      <div className="line-clamp-2 text-xs text-muted sm:line-clamp-1" title={sm}>{sm || '（概要情報なし）'}</div>
                      <div className="mt-0.5 text-[11px] text-muted">照会 {ago(r.fetched_at)}</div>
                    </div>
                    <div className="shrink-0 self-start pt-0.5">
                      {ws === 'watching' ? <span className="whitespace-nowrap text-xs text-accent">監視中</span>
                        : ws === 'resolved' ? <span className="whitespace-nowrap text-xs text-green-600">監視（解決）</span>
                        : <form action={watchCve}><input type="hidden" name="cve" value={r.cve} /><button className="whitespace-nowrap rounded-full border border-line px-2 py-0.5 text-xs hover:border-accent">監視に追加</button></form>}
                    </div>
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
