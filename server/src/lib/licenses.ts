// Per-component license enrichment, for license/obligation review grouped by project (system).
// Sources: deps.dev (npm, PyPI) and Packagist (PHP/composer) — the ecosystems where OSS-obligation risk
// (copyleft) actually lives for shipped applications. OS packages (rpm/deb) are out of scope here.
// Everything is cached in license_lookups keyed by (ecosystem, name, version); '' means "looked up,
// unknown" so it is never retried.
import { q } from './db';

const SUPPORTED = ['npm', 'PyPI', 'Packagist'];

// SPDX category for the UI. strong/weak copyleft are the "notable" ones to surface.
export type LicenseClass = 'strong' | 'weak' | 'permissive' | 'unknown' | 'other';
export function classifyLicense(lic: string | null): LicenseClass {
  const s = (lic ?? '').trim();
  if (!s || /non-standard|noassertion|unknown/i.test(s)) return 'unknown';
  if (/\bA?GPL/i.test(s) && !/LGPL/i.test(s)) return 'strong';      // GPL / AGPL
  if (/\b(LGPL|MPL|EPL|CDDL|CPL|EUPL|OSL)/i.test(s)) return 'weak'; // weak/file-level copyleft
  if (/\b(MIT|BSD|Apache|ISC|0BSD|Unlicense|Zlib|WTFPL|BlueOak|Python-2|PSF)/i.test(s)) return 'permissive';
  return 'other';
}
export const LICENSE_CLASS_LABEL: Record<LicenseClass, string> = {
  strong: '強いコピーレフト（GPL/AGPL）', weak: '弱いコピーレフト（LGPL/MPL等）',
  permissive: '寛容（MIT/BSD/Apache等）', other: 'その他', unknown: '不明',
};

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

async function getJson(url: string): Promise<unknown | null> {
  const ctl = new AbortController();
  const t = setTimeout(() => ctl.abort(), 10_000);
  try {
    const res = await fetch(url, { signal: ctl.signal, headers: { 'user-agent': 'minisoc2' } });
    if (!res.ok) return null;
    return await res.json();
  } catch { return null; } finally { clearTimeout(t); }
}

// PyPI project-name normalisation deps.dev expects: lowercase, runs of [-_.] collapsed to a single '-'.
const pypiNorm = (n: string) => n.toLowerCase().replace(/[-_.]+/g, '-');

async function fromDepsDev(sys: 'npm' | 'pypi', name: string, version: string): Promise<string> {
  const n = sys === 'pypi' ? pypiNorm(name) : name;
  const url = `https://api.deps.dev/v3/systems/${sys}/packages/${encodeURIComponent(n)}/versions/${encodeURIComponent(version)}`;
  const d = await getJson(url) as { licenses?: string[] } | null;
  const ls = d?.licenses?.filter(Boolean) ?? [];
  return ls.length ? ls.join(' AND ') : '';
}

// Packagist p2 is "minified": per version, a field is present only when it differs from the newer entry
// (list is newest-first), so carry the last seen license backwards. Fall back to the newest known license.
async function fromPackagist(name: string, version: string): Promise<string> {
  if (!name.includes('/')) return '';
  const d = await getJson(`https://repo.packagist.org/p2/${name}.json`) as { packages?: Record<string, { version: string; license?: string[] }[]> } | null;
  const vs = d?.packages?.[name];
  if (!vs?.length) return '';
  const want = version.replace(/^v/, '');
  let carried = '';
  let newest = '';
  for (const v of vs) {
    const lic = v.license?.filter(Boolean).join(' AND ') ?? '';
    if (lic) { carried = lic; if (!newest) newest = lic; }
    if (v.version.replace(/^v/, '') === want) return carried || newest;
  }
  return newest;
}

async function fetchOne(ecosystem: string, name: string, version: string): Promise<string> {
  if (ecosystem === 'npm') return fromDepsDev('npm', name, version);
  if (ecosystem === 'PyPI') return fromDepsDev('pypi', name, version);
  if (ecosystem === 'Packagist') return fromPackagist(name, version);
  return '';
}

// Copy cached licenses onto host_packages rows that are still unenriched (cheap, no network).
async function applyCache(): Promise<void> {
  await q(`UPDATE host_packages hp SET license = ll.license
           FROM license_lookups ll
           WHERE hp.license IS NULL AND ll.ecosystem=hp.ecosystem AND ll.name=hp.name AND ll.version=hp.version`);
}

// Worker step: fill in missing component licenses, bounded per run so a slow upstream can't stall.
export async function enrichLicenses(limit = 250): Promise<{ fetched: number }> {
  await applyCache();
  const todo = await q<{ ecosystem: string; name: string; version: string }>(
    `SELECT DISTINCT ecosystem, name, version FROM host_packages
     WHERE license IS NULL AND ecosystem = ANY($1::text[]) LIMIT $2`, [SUPPORTED, limit]);
  let fetched = 0;
  for (const p of todo) {
    const lic = await fetchOne(p.ecosystem, p.name, p.version);
    await q(`INSERT INTO license_lookups(ecosystem, name, version, license) VALUES ($1,$2,$3,$4)
             ON CONFLICT (ecosystem, name, version) DO UPDATE SET license=excluded.license, fetched_at=now()`,
      [p.ecosystem, p.name, p.version, lic]);
    fetched++;
    await sleep(100);
  }
  // Mark unsupported ecosystems as "looked up, unknown" so they don't count as pending forever.
  await q(`UPDATE host_packages SET license='' WHERE license IS NULL AND NOT (ecosystem = ANY($1::text[]))`, [SUPPORTED]);
  await applyCache();
  return { fetched };
}
