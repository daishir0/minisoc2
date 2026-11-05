import { randomUUID } from 'node:crypto';
import { currentUser } from '@/lib/auth';
import { q } from '@/lib/db';

// CycloneDX 1.6 VEX of every finding marked "not affected" (optionally for one host).
export async function GET(req: Request) {
  if (!(await currentUser())) return new Response('unauthorized', { status: 401 });
  const host = new URL(req.url).searchParams.get('host');
  const params: unknown[] = [];
  let hostFilter = '';
  if (host && /^[0-9a-f-]{36}$/.test(host)) {
    params.push(host);
    hostFilter = ' WHERE x.host_id=$1';
  }
  // Two "not affected" sources, both exported as CycloneDX VEX not_affected:
  //   1. findings.status='suppressed' — a whole finding marked not-affected (from the findings page).
  //   2. finding_vex — a PER-SYSTEM "影響なし" (from the remediation picker). These are filtered out of
  //      matching so they never surface as findings, but they are still real, justified judgments and
  //      belong in the external VEX/SBOM. Their version is the package's current installed version.
  const rows = await q<{ vuln_id: string; ecosystem: string; pkg: string; version: string; suppress_reason: string; suppress_note: string | null; suppressed_at: Date; host: string }>(
    `SELECT x.vuln_id, x.ecosystem, x.pkg, x.version, x.suppress_reason, x.suppress_note, x.suppressed_at, x.host FROM (
       SELECT f.vuln_id, f.ecosystem, f.pkg, f.version, f.suppress_reason, f.suppress_note, f.suppressed_at, h.name AS host, f.host_id
         FROM findings f JOIN hosts h ON h.id=f.host_id WHERE f.status='suppressed'
       UNION ALL
       SELECT fv.vuln_id, fv.ecosystem, fv.pkg,
              COALESCE((SELECT p.version FROM host_packages p WHERE p.host_id=fv.host_id AND p.ecosystem=fv.ecosystem AND p.name=fv.pkg LIMIT 1), '') AS version,
              fv.reason AS suppress_reason, fv.note AS suppress_note, fv.created_at AS suppressed_at, h.name AS host, fv.host_id
         FROM finding_vex fv JOIN hosts h ON h.id=fv.host_id
     ) x${hostFilter} ORDER BY x.vuln_id`,
    params,
  );
  const ref = (r: (typeof rows)[number]) => `${r.host}/${r.ecosystem}/${r.pkg}@${r.version.split(',')[0].trim()}`;
  const doc = {
    bomFormat: 'CycloneDX',
    specVersion: '1.6',
    serialNumber: `urn:uuid:${randomUUID()}`,
    version: 1,
    metadata: { timestamp: new Date().toISOString(), tools: { components: [{ type: 'application', name: 'minisoc2' }] } },
    components: [...new Map(rows.map((r) => [ref(r), { type: 'library', 'bom-ref': ref(r), name: r.pkg, version: r.version.split(',')[0].trim(), group: r.ecosystem }])).values()],
    vulnerabilities: rows.map((r) => ({
      id: r.vuln_id,
      source: /^CVE-/.test(r.vuln_id) ? { name: 'NVD', url: `https://nvd.nist.gov/vuln/detail/${r.vuln_id}` } : { name: 'OSV', url: `https://osv.dev/vulnerability/${r.vuln_id}` },
      analysis: { state: 'not_affected', justification: r.suppress_reason, detail: r.suppress_note ?? undefined, lastUpdated: new Date(r.suppressed_at).toISOString() },
      affects: [{ ref: ref(r) }],
    })),
  };
  return new Response(JSON.stringify(doc, null, 2), {
    headers: { 'content-type': 'application/vnd.cyclonedx+json', 'content-disposition': `attachment; filename="minisoc2-vex-${new Date().toISOString().slice(0, 10)}.json"` },
  });
}
