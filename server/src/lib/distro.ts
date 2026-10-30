// Distro security advisories, looked up per-CVE on demand. This is the operationally fast path:
// distro trackers (Ubuntu USN / security tracker) map a CVE to package + fixed version within hours,
// long before NVD finishes CPE analysis, and they cover OS/kernel packages that OSV/GHSA do not.
// Currently Ubuntu (dpkg) is implemented — the gap vs RPM hosts, which already get dnf advisories.
import { compareVersions } from './cvelookup';

export const UBUNTU_CODENAME: Record<string, string> = {
  '16.04': 'xenial', '18.04': 'bionic', '20.04': 'focal', '22.04': 'jammy',
  '23.04': 'lunar', '23.10': 'mantic', '24.04': 'noble', '24.10': 'oracular', '25.04': 'plucky',
};

export interface UbuntuPkgStatus { name: string; release: string; status: string; fixed: string }
export interface UbuntuCve { priority: string | null; pkgs: UbuntuPkgStatus[] }

interface RawUbuntu {
  priority?: string;
  packages?: { name: string; statuses?: { release_codename?: string; status?: string; description?: string }[] }[];
}

export async function fetchUbuntuCve(cve: string): Promise<UbuntuCve | null> {
  const ac = new AbortController();
  const t = setTimeout(() => ac.abort(), 10_000);
  try {
    const res = await fetch(`https://ubuntu.com/security/cves/${cve}.json`, { headers: { 'user-agent': 'minisoc2' }, signal: ac.signal });
    if (!res.ok) return null;
    const j = (await res.json()) as RawUbuntu;
    const pkgs: UbuntuPkgStatus[] = [];
    for (const p of j.packages ?? []) {
      for (const s of p.statuses ?? []) {
        if (!s.release_codename || !s.status) continue;
        pkgs.push({ name: p.name, release: s.release_codename, status: s.status, fixed: s.description ?? '' });
      }
    }
    return { priority: j.priority ?? null, pkgs };
  } catch {
    return null;
  } finally {
    clearTimeout(t);
  }
}

// Tracker package names a host package could be covered by. For kernels, Ubuntu tracks a per-series
// source (e.g. "linux-aws-6.8") plus the generic "linux-aws"/"linux"; the series comes from the
// installed version so a 6.8 kernel is never matched against a 5.15 advisory.
export function trackerCandidates(name: string, version = ''): { names: string[]; series: string | null } {
  const bin = name.match(/^linux-(?:image|headers|modules|tools)-\d+\.\d+\.\d+-\d+-(\w+)$/);
  const meta = name.match(/^linux-([a-z0-9]+)(?:-\d+\.\d+)?$/);
  if (bin || meta || name === 'linux') {
    const flavor = bin ? bin[1] : meta ? meta[1] : '';
    const series = (version.match(/^(\d+\.\d+)\./) ?? name.match(/-(\d+\.\d+)$/) ?? [])[1] ?? null;
    const cands = new Set<string>();
    if (flavor && flavor !== 'generic' && series) cands.add(`linux-${flavor}-${series}`);
    if (flavor && flavor !== 'generic') cands.add(`linux-${flavor}`);
    if (series) cands.add(`linux-hwe-${series}`);
    cands.add('linux');
    return { names: [...cands], series };
  }
  return { names: [name], series: null };
}

// A status that means "still vulnerable" (fix not yet available) vs "not applicable".
function statusKind(status: string): 'vuln' | 'fixedWhenOlder' | 'skip' {
  const s = status.toLowerCase();
  if (s === 'released') return 'fixedWhenOlder';           // compare version
  if (s === 'pending' || s === 'needed' || s === 'needs-triage' || s === 'deferred') return 'vuln';
  return 'skip';                                            // not-affected, DNE, ignored, not-vulnerable
}

export interface DistroVerdict { red: string[]; green: string[]; matched: boolean }

// Match a host's dpkg packages against the Ubuntu advisory for one release.
export function ubuntuVerdict(release: string, osPkgs: { name: string; version: string }[], uc: UbuntuCve): DistroVerdict {
  const red: string[] = [];
  const green: string[] = [];
  let matched = false;
  const forRelease = uc.pkgs.filter((p) => p.release === release);
  if (!forRelease.length) return { red, green, matched };
  const byName = new Map<string, UbuntuPkgStatus>();
  for (const p of forRelease) byName.set(p.name, p);

  for (const ip of osPkgs) {
    const { names, series } = trackerCandidates(ip.name, ip.version);
    for (const cand of names) {
      const tp = byName.get(cand);
      if (!tp) continue;
      const kind = statusKind(tp.status);
      if (kind === 'skip') continue;
      // for kernels, only trust an entry whose fixed version is in the same major.minor series
      if (series && tp.fixed && !tp.fixed.startsWith(series + '.')) continue;
      matched = true;
      if (kind === 'vuln') {
        red.push(`Ubuntu勧告：${cand}（${release}）は${tp.status === 'pending' ? '修正保留中（未リリース）' : '未修正'}＝脆弱。インストール中 ${ip.name} ${ip.version}`);
      } else if (tp.fixed) {
        const cmp = compareVersions(ip.version, tp.fixed);
        if (cmp < 0) red.push(`Ubuntu勧告：${ip.name} ${ip.version} は修正版 ${tp.fixed} 未満＝脆弱（${cand}/${release}）`);
        else green.push(`Ubuntu勧告：${ip.name} ${ip.version} は修正版 ${tp.fixed} 以上＝適用済み（${cand}/${release}）`);
      }
      break; // first matching candidate wins (most specific)
    }
  }
  return { red, green, matched };
}

// Does the CVE describe a component this host plainly runs, even if no advisory maps it yet?
// Used for provisional "requires review" triage of brand-new CVEs (source C).
export function classifyComponent(description: string): 'kernel' | null {
  return /\blinux kernel\b/i.test(description || '') ? 'kernel' : null;
}
