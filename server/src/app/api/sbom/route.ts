import { randomUUID } from 'node:crypto';
import { currentUser } from '@/lib/auth';
import { q, q1 } from '@/lib/db';

function purl(eco: string, name: string, version: string, osId: string): string | undefined {
  const v = encodeURIComponent(version);
  if (eco === 'npm') return `pkg:npm/${name.startsWith('@') ? `%40${name.slice(1)}` : name}@${v}`;
  if (eco === 'PyPI') return `pkg:pypi/${name}@${v}`;
  if (eco === 'Packagist') return `pkg:composer/${name}@${v}`;
  if (eco === 'rpm') return `pkg:rpm/${osId || 'linux'}/${name}@${v}`;
  if (/^(Debian|Ubuntu)/.test(eco)) return `pkg:deb/${eco.split(':')[0].toLowerCase()}/${name}@${v}`;
  if (/^Alpine/.test(eco)) return `pkg:apk/alpine/${name}@${v}`;
  return undefined;
}

// CycloneDX 1.6 SBOM of one system: its own dependencies, the runtime and OS packages its services
// use, and the packages excluded by path (kept, marked excluded). ?vex=1 adds vulnerability analysis.
export async function GET(req: Request) {
  if (!(await currentUser())) return new Response('unauthorized', { status: 401 });
  const u = new URL(req.url);
  const id = Number(u.searchParams.get('system'));
  const s = await q1<{ host_id: string; root: string; name: string; exposure: string; host: string; os_id: string; url: string }>(
    'SELECT s.host_id, s.root, s.name, s.exposure, s.url, h.name AS host, h.os_id FROM systems s JOIN hosts h ON h.id=s.host_id WHERE s.id=$1', [id],
  );
  if (!s) return new Response('not found', { status: 404 });
  const svcs = await q<{ runtime_root: string | null; os_pkg: string | null }>('SELECT runtime_root, os_pkg FROM host_services WHERE host_id=$1 AND system_root=$2', [s.host_id, s.root]);
  const runtimes = [...new Set(svcs.map((x) => x.runtime_root).filter((x): x is string => !!x))];
  const osPkgs = [...new Set(svcs.map((x) => x.os_pkg).filter((x): x is string => !!x))];
  const own = await q<{ ecosystem: string; name: string; version: string }>('SELECT ecosystem, name, version FROM host_packages WHERE host_id=$1 AND $2 = ANY(systems)', [s.host_id, s.root]);
  const rt = runtimes.length ? await q<{ ecosystem: string; name: string; version: string; root: string }>(
    'SELECT p.ecosystem, p.name, p.version, r AS root FROM host_packages p, unnest(p.systems) r WHERE p.host_id=$1 AND r = ANY($2)', [s.host_id, runtimes]) : [];
  const os = osPkgs.length ? await q<{ ecosystem: string; name: string; version: string }>(
    `SELECT ecosystem, name, version FROM host_packages WHERE host_id=$1 AND ecosystem NOT IN ('npm','PyPI','Packagist')
       AND (name = ANY($2) OR EXISTS (SELECT 1 FROM unnest($2::text[]) o WHERE name LIKE o || '-%'))`, [s.host_id, osPkgs]) : [];
  const excluded = await q<{ ecosystem: string; name: string; version: string; pattern: string; reason: string }>(
    `SELECT x.ecosystem, x.name, x.version, x.pattern, COALESCE(e.reason, '') AS reason FROM host_packages_excluded x
     LEFT JOIN system_excludes e ON e.pattern=x.pattern AND e.system_id=$3
     WHERE x.host_id=$1 AND x.system_root=$2`, [s.host_id, s.root, id]);

  const comps = new Map<string, Record<string, unknown>>();
  const put = (eco: string, name: string, version: string, props: { name: string; value: string }[]) => {
    const ref = purl(eco, name, version, s.os_id) ?? `${eco}:${name}@${version}`;
    if (comps.has(ref)) return;
    comps.set(ref, { type: 'library', 'bom-ref': ref, name, version, ...(purl(eco, name, version, s.os_id) ? { purl: ref } : {}), properties: props });
  };
  for (const p of own) put(p.ecosystem, p.name, p.version, [{ name: 'minisoc2:layer', value: 'application' }]);
  for (const p of rt) put(p.ecosystem, p.name, p.version, [{ name: 'minisoc2:layer', value: 'runtime' }, { name: 'minisoc2:runtime', value: p.root }]);
  for (const p of os) put(p.ecosystem, p.name, p.version, [{ name: 'minisoc2:layer', value: 'os' }]);
  for (const p of excluded) put(p.ecosystem, p.name, p.version, [{ name: 'minisoc2:excluded', value: 'true' }, { name: 'minisoc2:excludePattern', value: p.pattern }, { name: 'minisoc2:excludeReason', value: p.reason }]);

  const doc: Record<string, unknown> = {
    bomFormat: 'CycloneDX',
    specVersion: '1.6',
    serialNumber: `urn:uuid:${randomUUID()}`,
    version: 1,
    metadata: {
      timestamp: new Date().toISOString(),
      tools: { components: [{ type: 'application', name: 'minisoc2' }] },
      component: { type: 'application', 'bom-ref': `system:${id}`, name: s.name, properties: [
        { name: 'minisoc2:host', value: s.host }, { name: 'minisoc2:root', value: s.root }, { name: 'minisoc2:exposure', value: s.exposure },
        ...(s.url ? [{ name: 'minisoc2:url', value: s.url }] : []),
      ] },
    },
    components: [...comps.values()],
  };
  if (u.searchParams.get('vex') === '1') {
    const roots = [s.root, ...runtimes];
    const f = await q<{ vuln_id: string; ecosystem: string; pkg: string; version: string; status: string; suppress_reason: string | null; suppress_note: string | null; cvss: string | null }>(
      `SELECT vuln_id, ecosystem, pkg, version, status, suppress_reason, suppress_note, cvss FROM findings
       WHERE host_id=$1 AND status IN ('open','suppressed') AND (systems && $2::text[] OR (source='os-advisory' AND (pkg = ANY($3) OR EXISTS (SELECT 1 FROM unnest($3::text[]) o WHERE pkg LIKE o || '-%'))))`,
      [s.host_id, roots, osPkgs],
    );
    doc.vulnerabilities = f.map((v) => {
      const ref = purl(v.ecosystem, v.pkg, v.version.split(',')[0].trim(), s.os_id) ?? `${v.ecosystem}:${v.pkg}@${v.version.split(',')[0].trim()}`;
      return {
        id: v.vuln_id,
        ...(v.cvss ? { ratings: [{ score: Number(v.cvss), method: 'CVSSv31' }] } : {}),
        analysis: v.status === 'suppressed'
          ? { state: 'not_affected', justification: v.suppress_reason, detail: v.suppress_note ?? undefined }
          : { state: 'in_triage' },
        affects: [{ ref }],
      };
    });
  }
  const fname = `minisoc2-${s.name.replace(/[^\w.-]+/g, '_')}-${u.searchParams.get('vex') === '1' ? 'sbom-vex' : 'sbom'}-${new Date().toISOString().slice(0, 10)}.cdx.json`;
  return new Response(JSON.stringify(doc, null, 2), {
    headers: { 'content-type': 'application/vnd.cyclonedx+json', 'content-disposition': `attachment; filename="${fname}"` },
  });
}
