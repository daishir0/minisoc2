import { notFound } from 'next/navigation';
import Link from 'next/link';
import { Breadcrumbs, CRUMB } from '@/components/Breadcrumbs';
import { Card, Kev, Sev, ago, vulnLink } from '@/components/ui';
import { q, q1 } from '@/lib/db';
import { compareVersions } from '@/lib/version';

// Per-host "patch history": vulnerabilities that minisoc2 observed become resolved, newest first.
// The data already exists — findings carry status='resolved' and resolved_at (the moment an agent
// report first showed the vulnerable version gone) — so this view just reads it back as a timeline.

const DOT: Record<string, string> = {
  critical: 'bg-red-600', high: 'bg-orange-500', medium: 'bg-yellow-400', low: 'bg-sky-500', unknown: 'bg-slate-400',
};
const KIND: Record<string, { label: string; cls: string }> = {
  updated: { label: '更新', cls: 'bg-green-100 text-green-700 dark:bg-green-950 dark:text-green-200' },
  removed: { label: '削除', cls: 'bg-slate-200 text-slate-700 dark:bg-slate-800 dark:text-slate-200' },
  excluded: { label: '除外', cls: 'bg-indigo-100 text-indigo-700 dark:bg-indigo-950 dark:text-indigo-200' },
  resolved: { label: '解消', cls: 'bg-slate-200 text-slate-700 dark:bg-slate-800 dark:text-slate-200' },
};

const hi = (s: string): string => s.split(',').map((x) => x.trim()).filter(Boolean).sort(compareVersions).pop() ?? '';
const dayLabel = (d: Date): string => {
  const t = new Date(); const y = new Date(t); y.setDate(t.getDate() - 1);
  const k = (x: Date) => x.toLocaleDateString('ja-JP');
  if (k(d) === k(t)) return '今日';
  if (k(d) === k(y)) return '昨日';
  return d.toLocaleDateString('ja-JP', { year: 'numeric', month: 'long', day: 'numeric', weekday: 'short' });
};

export default async function HistoryPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  if (!/^[0-9a-f-]{36}$/.test(id)) notFound();
  const h = await q1<{ id: string; name: string }>('SELECT id, name FROM hosts WHERE id=$1', [id]);
  if (!h) notFound();

  const sysName = new Map((await q<{ root: string; name: string }>('SELECT root, name FROM systems WHERE host_id=$1', [id])).map((r) => [r.root, r.name]));
  const tot = (await q<{ total: string; kev: string; crit: string; high: string; medium: string; low: string }>(
    `SELECT count(*) total, count(*) FILTER (WHERE kev) kev,
       count(*) FILTER (WHERE NOT kev AND severity='critical') crit, count(*) FILTER (WHERE NOT kev AND severity='high') high,
       count(*) FILTER (WHERE NOT kev AND severity='medium') medium, count(*) FILTER (WHERE NOT kev AND severity='low') low
     FROM findings WHERE host_id=$1 AND status='resolved' AND resolved_at IS NOT NULL`, [id]))[0];
  const daily = await q<{ d: string; n: string }>(
    `SELECT to_char(date_trunc('day', resolved_at), 'MM/DD') d, count(*) n FROM findings
     WHERE host_id=$1 AND status='resolved' AND resolved_at > now() - interval '30 days' GROUP BY 1 ORDER BY 1`, [id]);
  const rows = await q<{ vuln_id: string; ecosystem: string; pkg: string; version: string; fixed: string; severity: string; kev: boolean; systems: string[]; resolved_at: Date; now_v: string | null; excluded: boolean }>(
    `SELECT f.vuln_id, f.ecosystem, f.pkg, f.version, f.fixed, f.severity, f.kev, f.systems, f.resolved_at,
       (SELECT string_agg(DISTINCT p.version, ',' ORDER BY p.version) FROM host_packages p WHERE p.host_id=f.host_id AND p.ecosystem=f.ecosystem AND p.name=f.pkg) AS now_v,
       EXISTS(SELECT 1 FROM host_packages_excluded x WHERE x.host_id=f.host_id AND x.ecosystem=f.ecosystem AND x.name=f.pkg) AS excluded
     FROM findings f WHERE f.host_id=$1 AND f.status='resolved' AND f.resolved_at IS NOT NULL
     ORDER BY f.resolved_at DESC LIMIT 300`, [id]);

  const dmax = Math.max(1, ...daily.map((x) => Number(x.n)));
  const recent30 = daily.reduce((s, x) => s + Number(x.n), 0);

  // group by resolved_at date, keeping newest-first order
  const groups: { day: Date; items: typeof rows }[] = [];
  for (const r of rows) {
    const d = new Date(r.resolved_at);
    const key = d.toLocaleDateString('ja-JP');
    const g = groups[groups.length - 1];
    if (g && g.day.toLocaleDateString('ja-JP') === key) g.items.push(r);
    else groups.push({ day: d, items: [r] });
  }

  const kindOf = (r: typeof rows[number]): keyof typeof KIND => {
    const before = hi(r.version); const after = hi(r.now_v ?? '');
    if (after && (!before || compareVersions(after, before) > 0)) return 'updated';
    if (!after && r.excluded) return 'excluded';
    if (!after) return 'removed';
    return 'resolved';
  };

  return (
    <>
      <Breadcrumbs items={[CRUMB.home, CRUMB.assets, CRUMB.hosts, { label: h.name, href: `/hosts/${h.id}` }, { label: '対処の記録' }]} />
      <div className="flex flex-wrap items-center gap-3">
        <h1 className="text-xl font-semibold">対処の記録</h1>
        <span className="text-sm text-muted">{h.name}</span>
        <Link className="btn-ghost ml-auto" href={`/hosts/${h.id}`}>← ホストへ戻る</Link>
      </div>

      <Card title="これまでに解消した脆弱性">
        <div className="flex flex-wrap items-end gap-6">
          <div>
            <div className="text-3xl font-semibold text-green-600">{tot.total}<span className="ml-1 text-base font-normal text-muted">件</span></div>
            <div className="mt-1 flex flex-wrap gap-2 text-xs">
              {Number(tot.kev) > 0 && <span className="flex items-center gap-1"><Kev /> {tot.kev}</span>}
              {(['crit', 'high', 'medium', 'low'] as const).map((k) => {
                const sev = k === 'crit' ? 'critical' : k; const n = Number(tot[k]);
                return n > 0 ? <span key={k} className="flex items-center gap-1"><Sev s={sev} /> {n}</span> : null;
              })}
            </div>
          </div>
          {daily.length > 0 && (
            <div className="min-w-0 flex-1">
              <div className="mb-1 text-xs text-muted">直近30日の改善（+{recent30}件）</div>
              <div className="flex h-16 items-end gap-0.5">
                {daily.map((x) => (
                  <div key={x.d} className="group relative flex-1" title={`${x.d}：${x.n}件`}>
                    <div className="w-full rounded-t bg-green-500/80" style={{ height: `${Math.max(6, (Number(x.n) / dmax) * 100)}%` }} />
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      </Card>

      {rows.length === 0 ? (
        <Card><p className="text-sm text-muted">まだ解消の記録はありません。脆弱性に対処してエージェントが次に報告すると、ここに時系列で積み上がっていきます。</p></Card>
      ) : (
        <Card title={`解消のタイムライン（新しい順・最大300件）`}>
          <div className="space-y-6">
            {groups.map((g, gi) => (
              <div key={gi}>
                <div className="mb-2 text-xs font-semibold text-muted">{dayLabel(g.day)}</div>
                <ol className="relative space-y-3 border-l border-line pl-4">
                  {g.items.map((r, i) => {
                    const before = hi(r.version); const after = hi(r.now_v ?? '');
                    const kind = kindOf(r); const k = KIND[kind];
                    const names = (r.systems ?? []).filter((x) => x !== '__os__').map((x) => sysName.get(x) ?? x);
                    return (
                      <li key={r.vuln_id + r.pkg + i} className="relative">
                        <span className={`absolute -left-[22px] top-1.5 h-2.5 w-2.5 rounded-full ring-2 ring-panel ${r.kev ? 'bg-red-700' : DOT[r.severity] ?? DOT.unknown}`} />
                        <div className="flex flex-wrap items-center gap-x-2 gap-y-1 text-sm">
                          <span className="text-green-600">✅</span>
                          {r.kev ? <Kev /> : <Sev s={r.severity} />}
                          {vulnLink(r.vuln_id)}
                          <span className="font-mono text-xs">{r.pkg}</span>
                          <span className="font-mono text-xs text-muted">
                            {before || '—'}{after ? <> → <b className="text-fg">{after}</b></> : null}
                          </span>
                          <span className={`rounded px-1.5 py-0.5 text-[10px] ${k.cls}`}>{k.label}</span>
                          <span className="ml-auto whitespace-nowrap text-xs text-muted" title={new Date(r.resolved_at).toLocaleString('ja-JP')}>{ago(r.resolved_at)}に確認</span>
                        </div>
                        {names.length > 0 && <div className="mt-0.5 text-[11px] text-muted">{names.join('、')}</div>}
                      </li>
                    );
                  })}
                </ol>
              </div>
            ))}
          </div>
        </Card>
      )}
    </>
  );
}
