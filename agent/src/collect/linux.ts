// Linux collectors: OS identity, installed packages, pending security updates, host state.
import { readdirSync } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';
import type { CollectError, ListenPort, OsAdvisory, Pkg } from '../types.js';
import { readText, run } from '../util.js';

export function osRelease(): Record<string, string> {
  const out: Record<string, string> = {};
  for (const line of (readText('/etc/os-release') ?? '').split('\n')) {
    const m = line.match(/^([A-Z_]+)=(.*)$/);
    if (m) out[m[1]] = m[2].replace(/^"|"$/g, '');
  }
  return out;
}

// OSV ecosystem name for dpkg/apk based distros; RPM distros use dnf advisories instead.
function osvEcosystem(rel: Record<string, string>): string | null {
  const id = rel.ID ?? '';
  const ver = rel.VERSION_ID ?? '';
  if (id === 'debian') return `Debian:${ver.split('.')[0]}`;
  if (id === 'ubuntu') return `Ubuntu:${ver}${/LTS/.test(rel.VERSION ?? '') ? ':LTS' : ''}`;
  if (id === 'alpine') return `Alpine:v${ver.split('.').slice(0, 2).join('.')}`;
  return null;
}

export async function linuxPackages(errors: CollectError[]): Promise<Pkg[]> {
  const rel = osRelease();
  const eco = osvEcosystem(rel);
  const rpm = await run('rpm', ['-qa', '--qf', '%{NAME}\t%{EPOCHNUM}:%{VERSION}-%{RELEASE}\n']);
  if (rpm.ok && rpm.stdout.trim()) {
    return rpm.stdout.trim().split('\n').map((l) => {
      const [name, version] = l.split('\t');
      return { ecosystem: 'rpm', name, version: version.replace(/^0:/, ''), source: 'rpm' };
    });
  }
  const dpkg = await run('dpkg-query', ['-W', '-f=${Package}\t${Version}\t${db:Status-Abbrev}\n']);
  if (dpkg.ok && dpkg.stdout.trim()) {
    return dpkg.stdout.trim().split('\n')
      .map((l) => l.split('\t'))
      .filter(([, , st]) => (st ?? '').startsWith('ii'))
      .map(([name, version]) => ({ ecosystem: eco ?? 'dpkg', name, version, source: 'dpkg' }));
  }
  const apk = await run('apk', ['info', '-v']);
  if (apk.ok && apk.stdout.trim()) {
    return apk.stdout.trim().split('\n').map((l) => {
      const m = l.match(/^(.+)-(\d[^-]*-r\d+)$/);
      return { ecosystem: eco ?? 'apk', name: m ? m[1] : l, version: m ? m[2] : '', source: 'apk' };
    });
  }
  errors.push({ step: 'packages', message: 'no supported package manager found (rpm/dpkg/apk)' });
  return [];
}

const SEV: Record<string, string> = { critical: 'critical', important: 'high', moderate: 'medium', medium: 'medium', low: 'low' };

// RPM distros ship their own advisory feed (ALAS, RHSA ...). --releasever=latest is required on
// Amazon Linux 2023: without it dnf stays pinned to the AMI snapshot and never sees new fixes.
export async function dnfAdvisories(errors: CollectError[], useSudo = false): Promise<OsAdvisory[] | null> {
  const which = await run('dnf', ['--version'], 20_000);
  if (!which.ok) return null;
  // As a normal user dnf keeps a private metadata cache and may re-download everything on each
  // run (minutes); through sudo it shares the system cache.
  const dnf = (a: string[], ms: number) => (useSudo && process.getuid?.() !== 0 ? run('sudo', ['-n', 'dnf', ...a], ms) : run('dnf', a, ms));
  const rel = osRelease();
  const args = ['-q', 'updateinfo', 'list', '--security'];
  if (rel.ID === 'amzn' && rel.VERSION_ID === '2023') args.push('--releasever=latest');
  const cves = await dnf([...args, 'cves'], 420_000);
  const ids = cves.ok ? await dnf(args, 180_000) : cves;
  if (!cves.ok) {
    errors.push({ step: 'osAdvisories', message: (cves.stderr.trim() || (cves.code === null ? 'dnf updateinfo timed out' : 'dnf updateinfo failed')).slice(0, 500) });
    return null;
  }
  // "ALAS2023-2026-1611 Important/Sec. ImageMagick-1:6.9.13.44-1.amzn2023.0.1.x86_64"
  const parse = (line: string) => {
    const m = line.trim().match(/^(\S+)\s+(\S+?)\/Sec\.\s+(\S+)$/);
    if (!m) return null;
    const nevra = m[3].replace(/\.(x86_64|aarch64|noarch|i686|src)$/, '');
    const pm = nevra.match(/^(.+)-((?:\d+:)?[^-]+-[^-]+)$/);
    return { id: m[1], severity: SEV[m[2].toLowerCase()] ?? 'unknown', pkg: pm ? pm[1] : nevra, fixed: pm ? pm[2] : '' };
  };
  const advisoryByPkgFix = new Map<string, string>();
  for (const l of ids.stdout.split('\n')) {
    const r = parse(l);
    if (r) advisoryByPkgFix.set(`${r.pkg}@${r.fixed}`, r.id);
  }
  const out: OsAdvisory[] = [];
  for (const l of cves.stdout.split('\n')) {
    const r = parse(l);
    if (r) out.push({ ...r, advisory: advisoryByPkgFix.get(`${r.pkg}@${r.fixed}`) });
  }
  return out;
}

function parseProcNet(file: string, proto: ListenPort['proto']): ListenPort[] {
  const text = readText(file);
  if (!text) return [];
  const out: ListenPort[] = [];
  for (const line of text.split('\n').slice(1)) {
    const f = line.trim().split(/\s+/);
    if (f.length < 4) continue;
    const isTcp = proto.startsWith('tcp');
    if (isTcp && f[3] !== '0A') continue; // LISTEN
    if (!isTcp && f[3] !== '07') continue; // UDP "unconnected" sockets bound locally
    const [hexAddr, hexPort] = f[1].split(':');
    let addr: string;
    if (hexAddr.length === 8) {
      addr = [3, 2, 1, 0].map((i) => parseInt(hexAddr.slice(i * 2, i * 2 + 2), 16)).join('.');
    } else {
      addr = /^0+$/.test(hexAddr) ? '::' : hexAddr === '00000000000000000000000001000000' ? '::1' : hexAddr;
    }
    out.push({ proto, addr, port: parseInt(hexPort, 16) });
  }
  return out;
}

export function linuxPorts(): ListenPort[] {
  const all = [
    ...parseProcNet('/proc/net/tcp', 'tcp'), ...parseProcNet('/proc/net/tcp6', 'tcp6'),
    ...parseProcNet('/proc/net/udp', 'udp'), ...parseProcNet('/proc/net/udp6', 'udp6'),
  ];
  const seen = new Set<string>();
  return all.filter((p) => {
    const k = `${p.proto}|${p.addr}|${p.port}`;
    if (seen.has(k)) return false;
    seen.add(k);
    return true;
  }).sort((a, b) => a.port - b.port);
}

export function linuxUsers(): string[] {
  return (readText('/etc/passwd') ?? '').split('\n')
    .map((l) => l.split(':'))
    .filter((f) => f.length >= 7 && !/(nologin|false|sync|shutdown|halt)$/.test(f[6]))
    .map((f) => f[0]);
}

// Files whose change matters for intrusion (accounts, privilege, persistence, remote access).
export function linuxWatchedFiles(): string[] {
  const files = ['/etc/passwd', '/etc/group', '/etc/sudoers', '/etc/crontab', '/etc/ssh/sshd_config', '/root/.ssh/authorized_keys'];
  for (const dir of ['/etc/sudoers.d', '/etc/cron.d']) {
    try {
      for (const f of readdirSync(dir)) files.push(join(dir, f));
    } catch {
      /* missing or unreadable */
    }
  }
  try {
    for (const u of readdirSync('/home')) files.push(`/home/${u}/.ssh/authorized_keys`);
  } catch {
    files.push(join(homedir(), '.ssh/authorized_keys'));
  }
  return files;
}

// Security advisories already installed: proof that a CVE is fixed on this host.
export async function dnfFixed(errors: CollectError[], useSudo = false): Promise<OsAdvisory[] | null> {
  const which = await run('dnf', ['--version'], 20_000);
  if (!which.ok) return null;
  const rel = osRelease();
  const args = ['-q', 'updateinfo', 'list', '--security', '--installed'];
  if (rel.ID === 'amzn' && rel.VERSION_ID === '2023') args.push('--releasever=latest');
  args.push('cves');
  const r = useSudo && process.getuid?.() !== 0 ? await run('sudo', ['-n', 'dnf', ...args], 300_000) : await run('dnf', args, 300_000);
  if (!r.ok) {
    errors.push({ step: 'osFixed', message: (r.stderr.trim() || 'dnf updateinfo --installed failed').slice(0, 300) });
    return null;
  }
  const out: OsAdvisory[] = [];
  for (const line of r.stdout.split('\n')) {
    const m = line.trim().match(/^(\S+)\s+(\S+?)\/Sec\.\s+(\S+)$/);
    if (!m) continue;
    const nevra = m[3].replace(/\.(x86_64|aarch64|noarch|i686|src)$/, '');
    const pm = nevra.match(/^(.+)-((?:\d+:)?[^-]+-[^-]+)$/);
    out.push({ id: m[1], severity: SEV[m[2].toLowerCase()] ?? 'unknown', pkg: pm ? pm[1] : nevra, fixed: pm ? pm[2] : '' });
  }
  return out;
}
