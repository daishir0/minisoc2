// Ubuntu USN database as the fix-version source for OS/kernel CVEs.
//
// Why: OSV lists Ubuntu kernel CVEs against the linux source package but almost never carries a fixed
// version, so they stay "open" forever even on a patched kernel. The Ubuntu per-CVE endpoint
// (ubuntu.com/security/cves/<CVE>.json) is ~800 KB each and, from some networks, unreachable — doing
// hundreds of those per pass is infeasible. The USN database is ONE compressed file (~45 MB bz2) that
// maps every USN to its CVEs and the fixed version per release/source. We fetch it once (cached), parse
// it in a short-lived child process (large heap, so the long-lived worker stays small), and serve
// per-CVE verdicts locally. This replaces the per-CVE network lookup entirely.
import { spawnSync } from 'node:child_process';
import { mkdtempSync, writeFileSync, existsSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { UbuntuCve } from './distro';

const USN_DB_URL = 'https://usn.ubuntu.com/usn-db/database.json.bz2';
const REFRESH_MS = 20 * 60 * 60 * 1000; // re-fetch at most ~daily
const FETCH_TIMEOUT_MS = 120_000;
const MIN_HEALTHY = 2000; // a real Ubuntu release maps thousands of CVEs; below this = partial/bad fetch

export type UsnMap = Map<string, Map<string, Record<string, string>>>; // release -> CVE -> {source: fixedVersion}

let cache: { at: number; map: UsnMap } | null = null;
let inflight: Promise<UsnMap> | null = null;

// A workspace under the OS temp dir; the compressed DB and decompressed JSON are transient.
const workDir = (() => {
  try { return mkdtempSync(join(tmpdir(), 'minisoc2-usn-')); } catch { return tmpdir(); }
})();

async function download(dest: string): Promise<void> {
  // usn.ubuntu.com is intermittently slow/unreachable from some networks, so retry a few times (and
  // prefer curl, which does IPv4/IPv6 Happy-Eyeballs fallback more reliably than Node's fetch). On a
  // run where every attempt fails, the caller keeps the previous cache and tries again next pass.
  const perTry = Math.max(20, Math.round(FETCH_TIMEOUT_MS / 1000 / 3));
  for (let attempt = 1; attempt <= 3; attempt++) {
    const curl = spawnSync('curl', ['-fsSL', '--max-time', String(perTry), '-A', 'minisoc2', '-o', dest, USN_DB_URL], { stdio: 'ignore' });
    if (curl.status === 0 && existsSync(dest) && statSync(dest).size > 0) return;
    await new Promise((r) => setTimeout(r, attempt * 2000));
  }
  // Last resort where curl is unavailable.
  const ac = new AbortController();
  const t = setTimeout(() => ac.abort(), FETCH_TIMEOUT_MS);
  try {
    const res = await fetch(USN_DB_URL, { headers: { 'user-agent': 'minisoc2' }, signal: ac.signal });
    if (!res.ok) throw new Error(`USN DB HTTP ${res.status}`);
    writeFileSync(dest, Buffer.from(await res.arrayBuffer()));
  } finally {
    clearTimeout(t);
  }
}

// Build the compact map for the given releases. Heavy work (decompress + ~355 MB JSON parse) runs in a
// child process so its memory is reclaimed immediately and never bloats the worker.
async function build(releases: string[]): Promise<UsnMap> {
  const bz2 = join(workDir, 'usn-db.json.bz2');
  const json = join(workDir, 'usn-db.json');
  await download(bz2);
  const un = spawnSync('bunzip2', ['-kf', bz2], { stdio: 'ignore' });
  if (un.status !== 0 || !existsSync(json)) throw new Error(`bunzip2 failed (status ${un.status})`);
  // Resolve the parser next to this module's compiled location; it ships beside the worker.
  const parser = join(process.cwd(), 'worker', 'usn-parse.mjs');
  const res = spawnSync(process.execPath, ['--max-old-space-size=4096', parser, json, releases.join(',')], {
    maxBuffer: 256 * 1024 * 1024,
    encoding: 'utf8',
  });
  if (res.status !== 0) throw new Error(`usn-parse failed (status ${res.status}): ${(res.stderr || '').slice(0, 300)}`);
  const parsed = JSON.parse(res.stdout) as Record<string, Record<string, Record<string, string>>>;
  const map: UsnMap = new Map();
  for (const [rel, cves] of Object.entries(parsed)) {
    const relMap = new Map<string, Record<string, string>>();
    for (const [cve, srcs] of Object.entries(cves)) relMap.set(cve, srcs);
    map.set(rel, relMap);
  }
  // Sanity floor: a real Ubuntu release maps thousands of CVEs. A tiny result means a truncated/partial
  // download or a bad parse — throw so getUsnMap keeps the PREVIOUS good cache instead of caching (and
  // serving for ~20h) a near-empty map that would wipe host_os_fixed and reopen handled findings.
  const biggest = Math.max(0, ...[...map.values()].map((m) => m.size));
  if (biggest < MIN_HEALTHY) throw new Error(`USN map too small (max ${biggest} < ${MIN_HEALTHY}) — treating as failed`);
  return map;
}

// Return the cached USN map, refreshing it (at most ~daily) for the given release codenames. On any
// fetch/parse failure the previous cache is kept; a first-time failure yields an empty map so callers
// simply find no verdict (safe: nothing is wrongly suppressed).
export async function getUsnMap(releases: string[]): Promise<UsnMap> {
  const fresh = cache && Date.now() - cache.at < REFRESH_MS;
  const covered = cache && releases.every((r) => cache!.map.has(r));
  if (fresh && covered) return cache!.map;
  if (inflight) return inflight;
  inflight = (async () => {
    try {
      const map = await build([...new Set(releases)]);
      cache = { at: Date.now(), map };
      return map;
    } catch (e) {
      if (cache) return cache.map; // keep stale data over nothing
      return new Map();
    } finally {
      inflight = null;
    }
  })();
  return inflight;
}

// Shape the USN fixes for one CVE/release as a UbuntuCve, so the existing ubuntuVerdict() can consume it
// unchanged. Every USN fix is a RELEASED fix carrying a version, so status is always "released".
export function usnCveFor(map: UsnMap, release: string, cve: string): UbuntuCve | null {
  const srcs = map.get(release)?.get(cve);
  if (!srcs) return null;
  const pkgs = Object.entries(srcs).map(([name, fixed]) => ({ name, release, status: 'released', fixed }));
  if (!pkgs.length) return null;
  return { priority: null, pkgs };
}
