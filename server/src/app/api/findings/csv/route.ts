import { currentUser } from '@/lib/auth';
import { q } from '@/lib/db';
import { buildFindingsWhere } from '@/lib/findingsQuery';
import { riskBucket, BUCKET_LABEL } from '@/lib/risk';

// CSV export of the findings list, honouring the same filters as the on-screen table (status / severity
// view / host / KEV / source / system / q). Browser-session auth; one row per finding, systems joined.
const STATUS_LABEL: Record<string, string> = { open: '未対応', suppressed: '影響なし(VEX)', resolved: '解消済み' };

// RFC 4180 quoting: wrap in quotes and double any embedded quote. Everything is quoted for safety.
const cell = (v: unknown) => `"${String(v ?? '').replace(/"/g, '""')}"`;

export async function GET(req: Request) {
  if (!(await currentUser())) return new Response('unauthorized', { status: 401 });
  const sp = Object.fromEntries(new URL(req.url).searchParams);
  const { whereSql, params, status } = await buildFindingsWhere(sp);
  const rows = await q<{
    host: string; systems: string[] | null; vuln_id: string; severity: string; kev: boolean; cvss: string | null;
    ecosystem: string; pkg: string; version: string; fixed: string; source: string; first_seen: Date;
    epss: number | null; pub: boolean;
  }>(
    `SELECT h.name AS host, f.systems, f.vuln_id, f.severity, f.kev, f.cvss, f.ecosystem, f.pkg, f.version, f.fixed, f.source, f.first_seen,
       (SELECT max(e.score) FROM epss e WHERE e.cve=f.vuln_id OR e.cve = ANY(SELECT unnest(v.aliases) FROM vulns v WHERE v.id=f.vuln_id)) AS epss,
       EXISTS(SELECT 1 FROM systems s WHERE s.host_id=f.host_id AND s.root = ANY(f.systems) AND s.exposure='public') AS pub
     FROM findings f JOIN hosts h ON h.id=f.host_id WHERE ${whereSql}
     ORDER BY f.kev DESC, pub DESC, CASE f.severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END, f.cvss DESC NULLS LAST, f.first_seen DESC`,
    params,
  );
  const header = ['host', 'system', 'cve', 'severity', 'kev', 'cvss', 'epss_pct', 'priority', 'ecosystem', 'package', 'version', 'fixed', 'source', 'status', 'first_seen'];
  const lines = [header.join(',')];
  for (const f of rows) {
    const bucket = BUCKET_LABEL[riskBucket({ kev: f.kev, epss: f.epss, exposure: f.pub ? 'public' : '', severity: f.severity })];
    const sys = (f.systems ?? []).map((s) => (s === '__os__' ? 'OSパッケージ' : s)).join(';');
    lines.push([
      f.host, sys, f.vuln_id, f.severity, f.kev ? 'true' : 'false', f.cvss ?? '',
      f.epss != null ? String(Math.round(f.epss * 100)) : '', bucket,
      f.ecosystem, f.pkg, f.version, f.fixed, f.source, STATUS_LABEL[status] ?? status,
      new Date(f.first_seen).toISOString().slice(0, 10),
    ].map(cell).join(','));
  }
  // BOM so Excel opens the UTF-8 (Japanese) correctly.
  const body = '﻿' + lines.join('\r\n') + '\r\n';
  const stamp = new Date().toISOString().slice(0, 10);
  return new Response(body, {
    headers: {
      'content-type': 'text/csv; charset=utf-8',
      'content-disposition': `attachment; filename="minisoc2-findings-${status}-${stamp}.csv"`,
    },
  });
}
