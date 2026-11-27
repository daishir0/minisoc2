import { currentUser } from '@/lib/auth';
import { q } from '@/lib/db';
import { classifyLicense } from '@/lib/licenses';
import { purl } from '@/lib/purl';

// Fleet-wide component inventory (the /sbom browser backend). Aggregates host_packages by
// (ecosystem, name, version) with a reverse-lookup of the hosts that carry it, its license, and whether
// any open finding on that package is KEV/critical. Server-side filtering + pagination because the fleet
// has ~13k distinct components. ?format=csv streams the filtered set (no paging, capped).
const APP_ECO = ['npm', 'PyPI', 'Packagist'];
const COPYLEFT = '(GPL|AGPL|LGPL|MPL|EPL|CDDL|EUPL|OSL)';
const PER = 50;

function filters(sp: URLSearchParams): { where: string; params: unknown[] } {
  const params: unknown[] = [];
  const where: string[] = [];
  const host = sp.get('host');
  if (host && /^[0-9a-f-]{36}$/.test(host)) { params.push(host); where.push(`hp.host_id=$${params.length}`); }
  const project = sp.get('project');
  if (project) { params.push(project); where.push(`$${params.length} = ANY(hp.systems)`); }
  const eco = sp.get('eco');
  if (eco && /^[\w:.-]{1,40}$/.test(eco)) { params.push(eco); where.push(`hp.ecosystem=$${params.length}`); }
  const layer = sp.get('layer');
  if (layer === 'app') where.push(`hp.ecosystem = ANY('{${APP_ECO.join(',')}}')`);
  else if (layer === 'os') where.push(`NOT (hp.ecosystem = ANY('{${APP_ECO.join(',')}}'))`);
  if (sp.get('license') === 'copyleft') where.push(`hp.license ~* '${COPYLEFT}'`);
  const qq = (sp.get('q') ?? '').trim().slice(0, 100);
  if (qq) { params.push(`%${qq.replace(/[%_]/g, '')}%`); where.push(`(hp.name ILIKE $${params.length} OR hp.license ILIKE $${params.length})`); }
  const vuln = sp.get('vuln');
  if (vuln === '1') where.push('(f.kev OR f.crit)');
  else if (vuln === 'kev') where.push('f.kev');
  return { where: where.length ? 'WHERE ' + where.join(' AND ') : '', params };
}

const SELECT = `
  FROM host_packages hp JOIN hosts h ON h.id=hp.host_id
  LEFT JOIN LATERAL unnest(hp.systems) AS sysr(root) ON true
  LEFT JOIN systems sy ON sy.host_id=hp.host_id AND sy.root=sysr.root
  LEFT JOIN (SELECT ecosystem, pkg, bool_or(kev) AS kev, bool_or(severity='critical') AS crit
             FROM findings WHERE status='open' GROUP BY ecosystem, pkg) f
    ON f.ecosystem=hp.ecosystem AND f.pkg=hp.name`;

interface Row { ecosystem: string; name: string; version: string; license: string | null; nhosts: string; hosts: string[]; nprojects: string; projects: string[]; kev: boolean | null; crit: boolean | null }

async function rows(where: string, params: unknown[], limit: number, offset: number): Promise<Row[]> {
  return q<Row>(
    `SELECT hp.ecosystem, hp.name, hp.version, max(hp.license) AS license,
       count(DISTINCT hp.host_id) AS nhosts, (array_agg(DISTINCT h.name))[1:5] AS hosts,
       count(DISTINCT coalesce(sy.name, sysr.root)) FILTER (WHERE sysr.root IS NOT NULL AND sysr.root <> '__os__') AS nprojects,
       (array_remove(array_agg(DISTINCT coalesce(sy.name, nullif(sysr.root,'__os__'))), NULL))[1:5] AS projects,
       bool_or(f.kev) AS kev, bool_or(f.crit) AS crit
     ${SELECT} ${where}
     GROUP BY hp.ecosystem, hp.name, hp.version
     ORDER BY bool_or(f.kev) DESC NULLS LAST, bool_or(f.crit) DESC NULLS LAST, hp.name
     LIMIT ${limit} OFFSET ${offset}`, params);
}

function toComp(r: Row) {
  const vuln = r.kev ? 'kev' : r.crit ? 'crit' : '';
  const clsMap = { strong: 'strong', weak: 'weak', permissive: 'perm', other: 'unk', unknown: 'unk' } as const;
  return {
    pkg: r.name, version: r.version, eco: r.ecosystem, license: r.license || '不明',
    cls: clsMap[classifyLicense(r.license)], purl: purl(r.ecosystem, r.name, r.version) ?? `${r.ecosystem}:${r.name}@${r.version}`,
    vuln, nhosts: Number(r.nhosts), hosts: r.hosts ?? [],
    nprojects: Number(r.nprojects ?? 0), projects: (r.projects ?? []).map((p) => p.split('/').pop() || p),
  };
}

export async function GET(req: Request) {
  if (!(await currentUser())) return Response.json({ error: 'unauthorized' }, { status: 401 });
  const url = new URL(req.url);
  const sp = url.searchParams;
  const { where, params } = filters(sp);

  if (sp.get('format') === 'csv') {
    const rs = await rows(where, params, 5000, 0);
    const cell = (v: unknown) => `"${String(v ?? '').replace(/"/g, '""')}"`;
    const head = ['ecosystem', 'package', 'version', 'license', 'vuln', 'hosts', 'host_count', 'projects', 'project_count', 'purl'];
    const lines = [head.join(',')];
    for (const r of rs.map(toComp)) lines.push([r.eco, r.pkg, r.version, r.license, r.vuln, r.hosts.join(';'), r.nhosts, r.projects.join(';'), r.nprojects, r.purl].map(cell).join(','));
    return new Response('﻿' + lines.join('\r\n') + '\r\n', {
      headers: { 'content-type': 'text/csv; charset=utf-8', 'content-disposition': `attachment; filename="minisoc2-components-${new Date().toISOString().slice(0, 10)}.csv"` },
    });
  }

  const page = Math.max(0, Number(sp.get('page') ?? 0) || 0);
  const totalRow = await q<{ n: string }>(`SELECT count(*) AS n FROM (SELECT 1 ${SELECT} ${where} GROUP BY hp.ecosystem, hp.name, hp.version) t`, params);
  const total = Number(totalRow[0]?.n ?? 0);
  const rs = await rows(where, params, PER, page * PER);
  return Response.json({ total, page, per: PER, rows: rs.map(toComp) });
}
