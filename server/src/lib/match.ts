// Vulnerability matching: OSV.dev for language/distro packages, plus the OS package manager's own
// advisories (dnf updateinfo) reported by the agent. Produces the per-host findings table.
import { raiseAlert } from './alerts';
import { recordEvent, snapshot } from './events';
import { markFeed } from './feeds';
import { q, q1 } from './db';
import { atLeast, cvss3Score, fromScore, normalizeLabel, sevRank, type Severity } from './severity';
import { getPolicy } from './settings';
import { OS_SYSTEM } from './systems';
import { compareDebian } from './version';

const OSV = 'https://api.osv.dev/v1';
const nul = (x: string) => x.replace(/\u0000/g, '').replace(/\\u0000/g, ''); // Postgres text/jsonb reject NUL

export function osvSupported(ecosystem: string): boolean {
  return ['npm', 'PyPI', 'Packagist', 'Go', 'crates.io', 'RubyGems', 'Maven', 'NuGet'].includes(ecosystem) || /^(Debian|Ubuntu|Alpine):/.test(ecosystem);
}

interface OsvVuln {
  id: string;
  aliases?: string[];
  summary?: string;
  details?: string;
  published?: string;
  modified?: string;
  severity?: { type: string; score: string }[];
  database_specific?: { severity?: string };
  affected?: {
    package?: { ecosystem: string; name: string };
    ranges?: { events: { introduced?: string; fixed?: string }[] }[];
    database_specific?: { severity?: string };
    ecosystem_specific?: { severity?: string };
  }[];
}

async function osvFetch(path: string, body?: unknown): Promise<unknown> {
  for (let attempt = 0; attempt < 3; attempt++) {
    const res = await fetch(`${OSV}${path}`, { signal: AbortSignal.timeout(30_000), ...(body ? { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) } : {}) });
    if (res.ok) return res.json();
    if (res.status === 404) return null;
    if (res.status < 500 && res.status !== 429) throw new Error(`OSV ${path} HTTP ${res.status}`);
    await new Promise((r) => setTimeout(r, 1000 * (attempt + 1)));
  }
  throw new Error(`OSV ${path} failed after retries`);
}

function severityOf(v: OsvVuln): { severity: Severity; cvss: number | null } {
  let best: number | null = null;
  for (const s of v.severity ?? []) {
    if (s.type === 'CVSS_V3') {
      const n = cvss3Score(s.score);
      if (n != null && (best == null || n > best)) best = n;
    }
  }
  if (best != null) return { severity: fromScore(best), cvss: best };
  const labels = [
    v.database_specific?.severity,
    ...(v.affected ?? []).flatMap((a) => [a.database_specific?.severity, a.ecosystem_specific?.severity]),
    ...(v.severity ?? []).filter((s) => !s.type.startsWith('CVSS')).map((s) => s.score),
  ].map(normalizeLabel).filter((x) => x !== 'unknown');
  labels.sort((a, b) => sevRank(a) - sevRank(b));
  return { severity: labels[0] ?? 'unknown', cvss: null };
}

function fixedMap(v: OsvVuln): Record<string, string[]> {
  const out: Record<string, string[]> = {};
  for (const a of v.affected ?? []) {
    if (!a.package) continue;
    const fixes = (a.ranges ?? []).flatMap((r) => r.events.map((e) => e.fixed).filter((x): x is string => !!x));
    if (fixes.length) out[`${a.package.ecosystem}/${a.package.name}`] = [...new Set([...(out[`${a.package.ecosystem}/${a.package.name}`] ?? []), ...fixes])];
  }
  return out;
}

async function storeVulns(ids: string[]): Promise<void> {
  const queue = [...ids];
  const worker = async () => {
    for (let id = queue.shift(); id; id = queue.shift()) {
      const v = (await osvFetch(`/vulns/${encodeURIComponent(id)}`)) as OsvVuln | null;
      if (!v) continue;
      const { severity, cvss } = severityOf(v);
      await q(
        `INSERT INTO vulns(id, aliases, summary, severity, cvss, published, modified, fixed, fetched_at)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8, now())
         ON CONFLICT (id) DO UPDATE SET aliases=EXCLUDED.aliases, summary=EXCLUDED.summary, severity=EXCLUDED.severity, cvss=EXCLUDED.cvss,
           published=EXCLUDED.published, modified=EXCLUDED.modified, fixed=EXCLUDED.fixed, fetched_at=now()`,
        [v.id, (v.aliases ?? []).map(nul), nul(v.summary || v.details || '').slice(0, 500), severity, cvss, v.published ?? null, v.modified ?? null, nul(JSON.stringify(fixedMap(v)))],
      );
    }
  };
  await Promise.all(Array.from({ length: 8 }, worker));
}

// Query OSV for every package of the host whose cache entry is missing or older than the TTL.
async function refreshCache(hostId: string, ttlHours: number): Promise<void> {
  const stale = await q<{ ecosystem: string; name: string; version: string }>(
    `SELECT DISTINCT p.ecosystem, p.name, p.version FROM host_packages p
     LEFT JOIN pkg_vuln_cache c ON c.ecosystem=p.ecosystem AND c.name=p.name AND c.version=p.version
     WHERE p.host_id=$1 AND (c.checked_at IS NULL OR c.checked_at < now() - ($2 || ' hours')::interval)`,
    [hostId, String(ttlHours)],
  );
  const pkgs = stale.filter((p) => osvSupported(p.ecosystem));
  const needDetail = new Set<string>();
  for (let i = 0; i < pkgs.length; i += 1000) {
    const batch = pkgs.slice(i, i + 1000);
    const res = (await osvFetch('/querybatch', {
      queries: batch.map((p) => ({ package: { ecosystem: p.ecosystem, name: p.name }, version: p.version })),
    })) as { results: { vulns?: { id: string; modified: string }[] }[] };
    const known = new Map(
      (await q<{ id: string; modified: Date | null }>('SELECT id, modified FROM vulns WHERE id = ANY($1)', [
        [...new Set(res.results.flatMap((r) => (r.vulns ?? []).map((v) => v.id)))],
      ])).map((r) => [r.id, r.modified]),
    );
    for (const r of res.results) {
      for (const v of r.vulns ?? []) {
        const m = known.get(v.id);
        if (m === undefined || (m && new Date(v.modified) > m)) needDetail.add(v.id);
      }
    }
    await q(
      `INSERT INTO pkg_vuln_cache(ecosystem, name, version, vuln_ids, checked_at)
       SELECT e, n, v, CASE WHEN ids = '' THEN '{}'::text[] ELSE string_to_array(ids, ',') END, now()
       FROM unnest($1::text[], $2::text[], $3::text[], $4::text[]) AS t(e, n, v, ids)
       ON CONFLICT (ecosystem, name, version) DO UPDATE SET vuln_ids=EXCLUDED.vuln_ids, checked_at=now()`,
      [batch.map((p) => p.ecosystem), batch.map((p) => p.name), batch.map((p) => p.version), res.results.map((r) => (r.vulns ?? []).map((v) => v.id).join(','))],
    );
  }
  await storeVulns([...needDetail]);
}

interface Candidate {
  vulnId: string;
  ecosystem: string;
  pkg: string;
  versions: Set<string>;
  fixed: Set<string>;
  severity: Severity;
  source: 'osv' | 'os-advisory';
  systems: Set<string>;
  cvss: number | null;
}

function preferCve(id: string, aliases: string[]): string {
  return [id, ...aliases].find((a) => /^CVE-\d{4}-\d+$/.test(a)) ?? id;
}

// A kernel package is one whose CVE is only exploitable through the kernel the host is actually
// RUNNING. Older kernel packages often stay installed as boot fallback; those are not the running
// code. Covers dpkg (Ubuntu/Debian) versioned images/modules/headers/tools, their flavour meta
// packages, and linux-base; and rpm (dnf) kernel* packages. Flavour-agnostic, no host-specific names.
function isKernelPackage(ecosystem: string, name: string): boolean {
  const n = name.toLowerCase();
  if (ecosystem === 'rpm') return n === 'kernel' || /^kernel-/.test(n);
  if (n === 'linux-base') return true;
  // versioned kernel packages carry an ABI like "6.8.0-1069"
  if (/^linux-(image|image-unsigned|modules|modules-extra|headers|tools|cloud-tools|buildinfo)-\d+\.\d+\.\d+-\d+/.test(n)) return true;
  // flavour meta packages: linux-<flavour>, linux-image-<flavour>, linux-headers-<flavour>, linux-tools-<flavour>
  if (/^linux(-image|-image-unsigned|-headers|-tools|-cloud-tools|-modules)?-(aws|generic|gcp|azure|kvm|oracle|lowlatency|virtual|raspi|gke|ibm|intel|realtime|lts-[a-z]+|hwe-[0-9.]+)(-edge|-[0-9.]+)?$/.test(n)) return true;
  return false;
}

// Strip an rpm epoch ("1:") and a uname/arch suffix so a running kernel version compares cleanly
// against an advisory's fixed version with compareVersions().
const forVerCompare = (v: string) => v.trim().replace(/^\d+:/, '').replace(/\.(x86_64|aarch64|arm64|armv7l|noarch|i[36]86)$/, '');

// The version of the kernel the host is RUNNING, from hosts.kernel (uname) mapped to the installed
// package: dpkg "linux-image-<uname>", or the rpm "kernel" whose version matches the booted release.
// Returns null when it cannot be determined (then the caller leaves findings untouched = safe default).
async function runningKernelVersion(hostId: string): Promise<string | null> {
  const h = await q1<{ kernel: string | null }>('SELECT kernel FROM hosts WHERE id=$1', [hostId]);
  const uname = h?.kernel?.trim();
  if (!uname) return null;
  const deb = await q1<{ version: string }>(
    "SELECT version FROM host_packages WHERE host_id=$1 AND name IN ($2, $3) ORDER BY name LIMIT 1",
    [hostId, `linux-image-${uname}`, `linux-image-unsigned-${uname}`],
  );
  if (deb?.version) return deb.version;
  const unameNoArch = forVerCompare(uname);
  const rpms = await q<{ version: string }>("SELECT version FROM host_packages WHERE host_id=$1 AND ecosystem='rpm' AND name='kernel'", [hostId]);
  const match = rpms.find((r) => forVerCompare(r.version) === unameNoArch);
  return match?.version ?? null;
}

// Running-kernel awareness: a kernel CVE is remediated once the host RUNS a fixed kernel, even if an
// older vulnerable kernel package is still installed (boot fallback). Drop such kernel candidates so
// they resolve; non-kernel packages and not-yet-fixed kernels (running < fixed) are left untouched.
function dropKernelCvesCoveredByRunningKernel(running: string, out: Map<string, Candidate>): void {
  const rk = forVerCompare(running);
  for (const [k, c] of out) {
    if (!isKernelPackage(c.ecosystem, c.pkg)) continue;
    const fixes = [...c.fixed].filter(Boolean);
    if (fixes.length && fixes.some((f) => compareDebian(rk, forVerCompare(f)) >= 0)) out.delete(k);
  }
}

async function candidates(hostId: string): Promise<Map<string, Candidate>> {
  const out = new Map<string, Candidate>();
  // packages that only appear in systems marked "ignored" produce no findings
  const ignored = new Set((await q<{ root: string }>('SELECT root FROM systems WHERE host_id=$1 AND ignored', [hostId])).map((r) => r.root));
  // Only registered (manually confirmed) projects are evaluated. Auto-detected projects are shown
  // as candidates for approval and produce no findings until registered. OS packages ('__os__')
  // are host-level and always evaluated, since the host itself is registered.
  const registered = new Set((await q<{ root: string }>("SELECT root FROM systems WHERE host_id=$1 AND origin='manual'", [hostId])).map((r) => r.root));
  // A shared Python env (conda/venv) is evaluated when a REGISTERED project actually runs in it (a
  // service of that project points to it). So the env's installed packages are checked once and shown
  // on each project as its "実行環境" — real installed versions, no per-project duplication.
  const evalRuntimes = new Set(
    (await q<{ runtime_root: string }>(
      'SELECT DISTINCT runtime_root FROM host_services WHERE host_id=$1 AND runtime_root IS NOT NULL AND system_root = ANY($2::text[])',
      [hostId, [...registered]],
    )).map((r) => r.runtime_root),
  );
  const evaluated = (x: string) => x === OS_SYSTEM || ((registered.has(x) || evalRuntimes.has(x)) && !ignored.has(x));
  // Per-system "not affected" judgments: remove the judged system from a finding so other systems that
  // share the same package keep it. If every system of a finding is judged out, the finding disappears.
  const vex = new Set(
    (await q<{ system_root: string; vuln_id: string; ecosystem: string; pkg: string }>(
      'SELECT system_root, vuln_id, ecosystem, pkg FROM finding_vex WHERE host_id=$1', [hostId],
    )).map((r) => `${r.system_root}\u0000${r.vuln_id}\u0000${r.ecosystem}\u0000${r.pkg}`),
  );
  // Ubuntu/Debian OS CVEs the vendor tracker confirms already fixed on this host — suppress the OSV
  // false positives (OSV lists them without a fixed version). Compared on the CVE id, prefix-stripped.
  const normCve = (s: string) => s.replace(/^(UBUNTU|DEBIAN)-/, '');
  const osFixed = new Set((await q<{ vuln_id: string; pkg: string }>('SELECT vuln_id, pkg FROM host_os_fixed WHERE host_id=$1', [hostId])).map((r) => `${normCve(r.vuln_id)}\u0000${r.pkg}`));
  const add = (c: Omit<Candidate, 'versions' | 'fixed' | 'systems' | 'cvss'> & { version: string; fixed: string[]; systems: string[]; cvss?: number | null }) => {
    const systems = c.systems.filter(evaluated).filter((x) => !vex.has(`${x}\u0000${c.vulnId}\u0000${c.ecosystem}\u0000${c.pkg}`));
    if (c.systems.length && !systems.length) return;
    const k = `${c.vulnId}\u0000${c.ecosystem}\u0000${c.pkg}`;
    const e = out.get(k) ?? { ...c, cvss: c.cvss ?? null, versions: new Set<string>(), fixed: new Set<string>(), systems: new Set<string>() };
    if (c.cvss != null && (e.cvss == null || c.cvss > e.cvss)) e.cvss = c.cvss;
    if (c.version) e.versions.add(c.version);
    c.fixed.forEach((f) => e.fixed.add(f));
    systems.forEach((x) => e.systems.add(x));
    if (sevRank(c.severity) < sevRank(e.severity)) e.severity = c.severity;
    out.set(k, e);
  };
  const osv = await q<{ ecosystem: string; name: string; version: string; id: string; aliases: string[]; severity: Severity; fixed: Record<string, string[]>; systems: string[]; cvss: string | null }>(
    `SELECT p.ecosystem, p.name, p.version, v.id, v.aliases, v.severity, v.fixed, p.systems, v.cvss
     FROM host_packages p JOIN pkg_vuln_cache c ON c.ecosystem=p.ecosystem AND c.name=p.name AND c.version=p.version
     JOIN vulns v ON v.id = ANY(c.vuln_ids) WHERE p.host_id=$1`,
    [hostId],
  );
  for (const r of osv) {
    const vid = preferCve(r.id, r.aliases);
    // vendor tracker is authoritative for OS packages: drop OSV OS CVEs it confirms already fixed here
    if (/^(Ubuntu|Debian):/.test(r.ecosystem) && osFixed.has(`${normCve(vid)}\u0000${r.name}`)) continue;
    add({ vulnId: vid, ecosystem: r.ecosystem, pkg: r.name, version: r.version, fixed: r.fixed[`${r.ecosystem}/${r.name}`] ?? [], severity: r.severity, source: 'osv', systems: r.systems ?? [], cvss: r.cvss == null ? null : Number(r.cvss) });
  }
  const adv = await q<{ vuln_id: string; severity: Severity; pkg: string; fixed: string; installed: string | null }>(
    `SELECT a.vuln_id, a.severity, a.pkg, a.fixed,
       (SELECT string_agg(version, ', ') FROM host_packages p WHERE p.host_id=a.host_id AND p.ecosystem='rpm' AND p.name=a.pkg) AS installed
     FROM host_os_advisories a WHERE a.host_id=$1`,
    [hostId],
  );
  for (const r of adv) add({ vulnId: r.vuln_id, ecosystem: 'rpm', pkg: r.pkg, version: r.installed ?? '', fixed: r.fixed ? [r.fixed] : [], severity: r.severity, source: 'os-advisory', systems: ['__os__'] });
  // Distro-tracker confirmed OS vulns (Ubuntu/Debian) not in OSV — standing findings on __os__.
  const distro = await q<{ vuln_id: string; pkg: string; installed: string; fixed: string }>('SELECT vuln_id, pkg, installed, fixed FROM host_distro_cves WHERE host_id=$1', [hostId]);
  for (const r of distro) add({ vulnId: r.vuln_id, ecosystem: 'os', pkg: r.pkg, version: r.installed, fixed: r.fixed ? [r.fixed] : [], severity: 'high', source: 'os-advisory', systems: ['__os__'] });
  const running = await runningKernelVersion(hostId);
  if (running) dropKernelCvesCoveredByRunningKernel(running, out);
  return out;
}

export async function matchHost(hostId: string): Promise<{ open: number; added: number; resolved: number }> {
  const policy = await getPolicy();
  const host = await q1<{ name: string; baseline_done: boolean }>('SELECT name, baseline_done FROM hosts WHERE id=$1', [hostId]);
  if (!host) return { open: 0, added: 0, resolved: 0 };
  // Capture when this match began. The inventory it operates on is read below; if a NEW report lands
  // while we run (ingest sets last_seen_at=now() + needs_match=true), clearing needs_match unconditionally
  // at the end would drop that new inventory until the daily full re-match. We instead clear it only when
  // no newer report arrived (last_seen_at <= matchStart). See the final UPDATE.
  const matchStart = new Date();
  try {
    await refreshCache(hostId, policy.osvCacheHours);
    await markFeed('osv', true);
  } catch (e) {
    await markFeed('osv', false, { error: e instanceof Error ? e.message : String(e) });
    // continue with whatever is cached: OS advisories do not depend on OSV
  }
  const cands = await candidates(hostId);
  // One scale everywhere: the NVD CVSS score decides the severity when known (9.0+ = critical).
  const scores = new Map((await q<{ cve: string; score: string | null }>('SELECT cve, score FROM cve_scores WHERE cve = ANY($1) AND score IS NOT NULL', [[...new Set([...cands.values()].map((c) => c.vulnId))]])).map((r) => [r.cve, Number(r.score)]));
  for (const c of cands.values()) {
    const nvd = scores.get(c.vulnId);
    if (nvd != null) c.cvss = nvd;
    if (c.cvss != null) c.severity = fromScore(c.cvss);
  }
  const kev = new Set((await q<{ cve: string }>('SELECT cve FROM kev WHERE cve = ANY($1)', [[...new Set([...cands.values()].map((c) => c.vulnId))]])).map((r) => r.cve));
  const watch = new Set((await q<{ cve: string }>('SELECT cve FROM watch_cves')).map((r) => r.cve));
  const existing = new Map(
    (await q<{ id: string; vuln_id: string; ecosystem: string; pkg: string; status: string; kev: boolean; severity: string; systems: string[] }>(
      'SELECT id, vuln_id, ecosystem, pkg, status, kev, severity, systems FROM findings WHERE host_id=$1', [hostId],
    )).map((f) => [`${f.vuln_id}\u0000${f.ecosystem}\u0000${f.pkg}`, f]),
  );

  // A source seen for the first time on this host (e.g. OS advisories that started working later)
  // is a baseline too: thousands of existing issues must not become thousands of alerts.
  const knownSources = new Set((await q1<{ s: string[] }>('SELECT baseline_sources AS s FROM hosts WHERE id=$1', [hostId]))?.s ?? []);
  const quietSource = (src: string) => !host.baseline_done || !knownSources.has(src);
  const newSystems = new Set((await q<{ root: string }>('SELECT root FROM systems WHERE host_id=$1 AND NOT baselined', [hostId])).map((r) => r.root));
  // findings that only live in systems seen for the first time are part of that system's baseline
  const quietSystems = (c: Candidate) => c.systems.size > 0 && [...c.systems].every((x) => newSystems.has(x));
  let added = 0;
  const sysName = new Map((await q<{ root: string; name: string }>('SELECT root, name FROM systems WHERE host_id=$1', [hostId])).map((r) => [r.root, r.name]));
  const label = (c: Candidate) => {
    const names = [...c.systems].filter((x) => x !== '__os__').map((x) => sysName.get(x) ?? x);
    return `${c.vulnId}（${c.pkg} ${[...c.versions].slice(0, 3).join(', ')}${names.length ? ` / ${names.slice(0, 3).join(', ')}${names.length > 3 ? ` 他${names.length - 3}` : ''}` : ''}）`;
  };
  // change events, aggregated per system for this run
  const ev = new Map<string, { kev: number; critical: number; high: number; medium: number; low: number; pkgs: Set<string> }>();
  const bump = (root: string, sev: string, isKev: boolean, pkg: string) => {
    const e = ev.get(root) ?? { kev: 0, critical: 0, high: 0, medium: 0, low: 0, pkgs: new Set<string>() };
    if (isKev) e.kev++;
    else if (sev in e) (e as unknown as Record<string, number>)[sev]++;
    if (e.pkgs.size < 3) e.pkgs.add(pkg);
    ev.set(root, e);
  };
  const kevAdded: Candidate[] = [];
  for (const [k, c] of cands) {
    const isKev = kev.has(c.vulnId);
    const versions = [...c.versions].join(', ').slice(0, 500);
    const fixed = [...c.fixed].slice(0, 5).join(', ');
    const f = existing.get(k);
    existing.delete(k);
    if (!f) {
      await q(
        `INSERT INTO findings(host_id, vuln_id, ecosystem, pkg, version, fixed, severity, kev, source, systems, cvss) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
         ON CONFLICT (host_id, vuln_id, ecosystem, pkg) DO NOTHING`,
        [hostId, c.vulnId, c.ecosystem, c.pkg, versions, fixed, c.severity, isKev, c.source, [...c.systems], c.cvss],
      );
      added++;
    } else {
      const reopened = f.status === 'resolved';
      await q(
        `UPDATE findings SET version=$2, fixed=$3, severity=$4, kev=$5, systems=$6, cvss=$7, last_seen=now(),
           status = CASE WHEN status='resolved' THEN 'open' ELSE status END,
           resolved_at = CASE WHEN status='resolved' THEN NULL ELSE resolved_at END,
           first_seen = CASE WHEN status='resolved' THEN now() ELSE first_seen END
         WHERE id=$1`,
        [f.id, versions, fixed, c.severity, isKev, [...c.systems], c.cvss],
      );
      if (reopened) added++;
      if (isKev && !f.kev && f.status !== 'suppressed') {
        kevAdded.push(c);
        await raiseAlert({ kind: 'kev', severity: 'critical', hostId, title: `[${host.name}] 悪用が確認されました（CISA KEV）：${label(c)}`, detail: fixed ? `修正版：${fixed}` : '', dedupeKey: `kev:${hostId}:${k}` });
      }
      if (!reopened) continue;
    }
    if (host.baseline_done && !quietSource(c.source) && !quietSystems(c)) for (const root of c.systems) bump(root, c.severity, isKev, c.pkg);
    if (watch.has(c.vulnId)) {
      await raiseAlert({ kind: 'watch', severity: 'high', hostId, title: `[${host.name}] 監視中のCVEを検出：${label(c)}`, detail: fixed ? `修正版：${fixed}` : '修正版の情報なし', dedupeKey: `watch:${hostId}:${k}:${Date.now()}` });
    } else if (!quietSource(c.source) && !quietSystems(c) && ((isKev && policy.notifyKev) || atLeast(c.severity, policy.notifyMinSeverity))) {
      await raiseAlert({
        kind: isKev ? 'kev' : 'vuln',
        severity: isKev ? 'critical' : (c.severity as 'critical' | 'high' | 'medium' | 'low'),
        hostId,
        title: `[${host.name}] ${isKev ? '【悪用確認済み】' : ''}${label(c)}`,
        detail: [c.source === 'os-advisory' ? 'OSのセキュリティ更新あり' : 'アプリ依存の脆弱性', fixed && `修正版：${fixed}`].filter(Boolean).join(' / '),
        dedupeKey: `vuln:${hostId}:${k}:${Date.now()}`,
      });
    }
  }

  // Whatever was OPEN but no longer matches has been fixed. Deliberately NOT 'suppressed': a "影響なし"
  // judgment must survive a transient inventory gap (a partially-failed collection, or an exclude being
  // toggled). If we resolved suppressed findings here, a later re-appearance would come back as
  // status='open' with first_seen=now() and re-alert, silently discarding the human's VEX decision.
  // A genuinely-removed package simply keeps its (harmless, non-alerting) suppressed row.
  const gone = [...existing.values()].filter((f) => f.status === 'open');
  if (gone.length) {
    await q("UPDATE findings SET status='resolved', resolved_at=now() WHERE id = ANY($1::bigint[])", [gone.map((f) => f.id)]);
    for (const f of gone) {
      if (watch.has(f.vuln_id)) {
        await raiseAlert({ kind: 'watch', severity: 'info', hostId, title: `[${host.name}] 監視中の ${f.vuln_id}（${f.pkg}）が解消されました`, dedupeKey: `watch-fixed:${hostId}:${f.id}:${Date.now()}` });
      }
    }
  }

  const sysLabel = (root: string) => (root === '__os__' ? `${host.name} OS` : `${host.name}／${sysName.get(root) ?? root}`);
  const fmt = (e: { kev: number; critical: number; high: number; medium: number; low: number }) =>
    [e.kev && `KEV ${e.kev}`, e.critical && `緊急 ${e.critical}`, e.high && `高 ${e.high}`, e.medium && `中 ${e.medium}`, e.low && `低 ${e.low}`].filter(Boolean).join('・');
  for (const [root, e] of ev) {
    const total = e.kev + e.critical + e.high + e.medium + e.low;
    if (!total) continue;
    await recordEvent({ hostId, systemRoot: root, kind: 'vuln_new', important: e.kev + e.critical > 0, count: total,
      title: `${sysLabel(root)}：新しい脆弱性 ${fmt(e)}（${[...e.pkgs].join('、')}${total > e.pkgs.size ? ' ほか' : ''}）` });
  }
  const goneBy = new Map<string, { kev: number; critical: number; high: number; medium: number; low: number; pkgs: Set<string> }>();
  for (const f of gone) for (const root of f.systems?.length ? f.systems : ['__os__']) {
    const e = goneBy.get(root) ?? { kev: 0, critical: 0, high: 0, medium: 0, low: 0, pkgs: new Set<string>() };
    if (f.kev) e.kev++;
    else if (f.severity in e) (e as unknown as Record<string, number>)[f.severity]++;
    if (e.pkgs.size < 3) e.pkgs.add(f.pkg);
    goneBy.set(root, e);
  }
  for (const [root, e] of goneBy) {
    const total = e.kev + e.critical + e.high + e.medium + e.low;
    if (!total) continue;
    await recordEvent({ hostId, systemRoot: root, kind: 'vuln_resolved', important: e.kev + e.critical > 0, count: total,
      title: `${sysLabel(root)}：解消 ${fmt(e)}（${[...e.pkgs].join('、')}${total > e.pkgs.size ? ' ほか' : ''}）` });
  }
  if (kevAdded.length) {
    await recordEvent({ hostId, kind: 'kev_added', important: true, count: kevAdded.length,
      title: `${host.name}：既存の脆弱性 ${kevAdded.length}件が CISA KEV に追加（${[...new Set(kevAdded.map((c) => c.pkg))].slice(0, 3).join('、')}）` });
  }

  if (host.baseline_done && newSystems.size) {
    const names = new Map((await q<{ root: string; name: string }>('SELECT root, name FROM systems WHERE host_id=$1', [hostId])).map((r) => [r.root, r.name]));
    for (const root of newSystems) {
      const n = [...cands.values()].filter((c) => c.systems.has(root)).length;
      if (!n) continue;
      const imp = [...cands.values()].filter((c) => c.systems.has(root) && (kev.has(c.vulnId) || c.severity === 'critical')).length;
      await recordEvent({ hostId, systemRoot: root, kind: 'system_new', important: imp > 0, count: n,
        title: `${host.name}：新しいシステム「${names.get(root) ?? root}」を検出（未対応 ${n}件${imp ? `、うち KEV・緊急 ${imp}件` : ''}を基準線に）` });
      await raiseAlert({
        kind: 'baseline', severity: 'info', hostId,
        title: `[${host.name}] 新しいシステム「${names.get(root) ?? root}」を検出：未対応の脆弱性 ${n}件を基準線にしました`,
        detail: '以降は新しく見つかったものだけを通知します。',
        dedupeKey: `baseline:${hostId}:system:${root}`,
      });
    }
  }
  await q('UPDATE systems SET baselined=true WHERE host_id=$1 AND NOT baselined', [hostId]);

  const newSources = host.baseline_done ? [...new Set([...cands.values()].map((c) => c.source))].filter((x) => !knownSources.has(x)) : [];
  for (const src of newSources) {
    const n = [...cands.values()].filter((c) => c.source === src).length;
    await raiseAlert({
      kind: 'baseline', severity: 'info', hostId,
      title: `[${host.name}] ${src === 'os-advisory' ? 'OSの未適用セキュリティ更新' : 'アプリ依存の脆弱性'}の取得を開始：${n}件を基準線にしました`,
      detail: '以降は新しく見つかったものだけを通知します。',
      dedupeKey: `baseline:${hostId}:${src}`,
    });
  }

  if (!host.baseline_done) {
    await recordEvent({ hostId, kind: 'system_new', important: false, count: cands.size, title: `${host.name}：ホストを登録（未対応 ${cands.size}件を基準線に）` });
    const c = await q<{ severity: string; n: string; k: string }>(
      "SELECT severity, count(*) AS n, count(*) FILTER (WHERE kev) AS k FROM findings WHERE host_id=$1 AND status='open' GROUP BY severity", [hostId],
    );
    const by = Object.fromEntries(c.map((r) => [r.severity, Number(r.n)]));
    const kevN = c.reduce((s, r) => s + Number(r.k), 0);
    await raiseAlert({
      kind: 'baseline', severity: 'info', hostId,
      title: `[${host.name}] 登録完了：未対応の脆弱性 ${c.reduce((s, r) => s + Number(r.n), 0)}件を基準線にしました`,
      detail: `緊急 ${by.critical ?? 0} / 高 ${by.high ?? 0} / 中 ${by.medium ?? 0} / 低 ${by.low ?? 0} / 不明 ${by.unknown ?? 0} / KEV ${kevN}\n以降は新しく見つかったものだけを通知します。`,
      dedupeKey: `baseline:${hostId}`,
    });
  }
  await snapshot(hostId);
  const sources = [...new Set([...knownSources, ...[...cands.values()].map((c) => c.source)])];
  // Clear needs_match ONLY if no newer report arrived while we matched (see matchStart). If one did,
  // leave the flag set so the next tick re-matches the fresh inventory instead of waiting for the
  // daily full re-match.
  await q('UPDATE hosts SET needs_match = COALESCE(last_seen_at > $3, false), baseline_done=true, baseline_sources=$2 WHERE id=$1', [hostId, sources, matchStart]);
  const open = await q1<{ n: string }>("SELECT count(*) AS n FROM findings WHERE host_id=$1 AND status='open'", [hostId]);
  return { open: Number(open?.n ?? 0), added, resolved: gone.length };
}
