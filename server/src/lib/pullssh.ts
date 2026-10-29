// Pull-type collection over read-only SSH, for hosts that cannot run the agent (shared hosting).
// One SSH call runs a read-only shell script; its delimited output is parsed into the same Report
// shape push agents send, then fed through the normal ingest/match pipeline. Nothing is ever
// written on the remote host and sudo is never used. Credentials are decrypted only in-process.
import { spawn } from 'node:child_process';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { q, q1 } from './db';
import { decrypt } from './secrets';
import { ingestReport, type HostRow } from './ingest';
import { ingestLogs } from './logs';
import type { LogEntry, Pkg, Report } from './payload';

export interface PullTarget {
  host_id: string;
  ssh_host: string;
  ssh_port: number;
  ssh_user: string;
  auth: 'key' | 'password';
  secret_enc: string;
  scan_paths: string[];
  log_globs: string[];
  log_state: Record<string, number>;
}

// Paths come from the admin; keep them to a safe charset so they cannot break out of the script.
export function safePath(p: string): boolean {
  return /^[A-Za-z0-9 ._/*~-]{1,512}$/.test(p) && !p.includes('..');
}
const sh = (p: string) => `'${p.replace(/'/g, "'\\''")}'`;

const LOCK_MAX = 400;          // lockfiles
const FILE_MAX = 4 * 1024 * 1024;  // bytes per lockfile
const LOG_CHUNK = 8 * 1024 * 1024; // bytes read per log file per poll

function buildScript(t: PullTarget): string {
  const scan = t.scan_paths.filter(safePath);
  const logs = t.log_globs.filter(safePath);
  const findLocks = scan.length
    ? `find ${scan.map(sh).join(' ')} -maxdepth 6 \\( -name composer.lock -o -name package-lock.json -o -name requirements.txt -o -name 'requirements-*.txt' \\) -type f 2>/dev/null | head -n ${LOCK_MAX}`
    : 'true';
  // log offsets are templated in so a single round-trip reads only the growth since last time
  const logBlocks = logs.map((g) => `for f in ${sh(g)}; do [ -f "$f" ] || continue; sz=$(stat -c %s "$f" 2>/dev/null || echo 0); printf '@@LOG %s %s@@\\n' "$f" "$sz"; prev=$(getoff "$f"); if [ "$sz" -lt "$prev" ]; then prev=0; fi; if [ "$sz" -gt "$prev" ]; then tail -c +$((prev+1)) "$f" 2>/dev/null | head -c ${LOG_CHUNK} | base64 | tr -d '\\n'; fi; printf '\\n@@ENDLOG@@\\n'; done`).join('\n');
  const offs = Object.entries(t.log_state).filter(([p]) => safePath(p)).map(([p, n]) => `${p}\t${n}`).join('\n');
  return `#!/bin/sh
set -u
getoff() { awk -F'\\t' -v k="$1" '$1==k{print $2; f=1} END{if(!f)print 0}' <<EOF2
${offs}
EOF2
}
echo '@@OSREL@@'; cat /etc/os-release 2>/dev/null; uname -srm 2>/dev/null
echo '@@RUNTIME@@'
for c in php python3 python node nodejs ruby perl composer; do v=$(command -v "$c" 2>/dev/null) && printf '%s\\t%s\\n' "$c" "$("$c" --version 2>&1 | head -n1)"; done
echo '@@PKG@@'
if command -v rpm >/dev/null 2>&1; then rpm -qa --qf '%{NAME}\\t%{VERSION}-%{RELEASE}\\n' 2>/dev/null;
elif command -v dpkg-query >/dev/null 2>&1; then dpkg-query -W -f='\${Package}\\t\${Version}\\n' 2>/dev/null;
elif command -v apk >/dev/null 2>&1; then apk info -v 2>/dev/null; fi
echo '@@PORTS@@'; (ss -tlnH 2>/dev/null || netstat -tln 2>/dev/null) | head -n 200
echo '@@HASH@@'
for f in "$HOME/.ssh/authorized_keys" "$HOME/.ssh/known_hosts" "$HOME/.ssh/config"; do [ -f "$f" ] && sha256sum "$f" 2>/dev/null; done
crontab -l 2>/dev/null | sha256sum | sed 's#-#crontab#'
echo '@@LOCKS@@'
${findLocks} | while read -r f; do sz=$(stat -c %s "$f" 2>/dev/null || echo 0); [ "$sz" -gt ${FILE_MAX} ] && continue; printf '@@LOCK %s %s@@\\n' "$f" "$sz"; base64 < "$f" | tr -d '\\n'; printf '\\n@@ENDLOCK@@\\n'; done
echo '@@LOGS@@'
${logBlocks}
echo '@@DONE@@'
`;
}

function runRemote(t: PullTarget, script: string, timeoutMs = 180_000): Promise<{ code: number; stdout: string; stderr: string }> {
  return new Promise((resolve) => {
    const dir = mkdtempSync(join(tmpdir(), 'minisoc2-pull-'));
    const known = join(dir, 'known_hosts');
    const opts = ['-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=accept-new', '-o', `UserKnownHostsFile=${known}`,
      '-o', 'ConnectTimeout=20', '-o', 'ServerAliveInterval=10', '-p', String(t.ssh_port)];
    let cmd = 'ssh';
    let args: string[];
    const env = { ...process.env };
    if (t.auth === 'key') {
      const key = join(dir, 'id');
      writeFileSync(key, decrypt(t.secret_enc).replace(/\s+$/, '') + '\n', { mode: 0o600 });
      args = [...opts, '-o', 'IdentitiesOnly=yes', '-i', key, `${t.ssh_user}@${t.ssh_host}`, 'sh', '-s'];
    } else {
      cmd = 'sshpass';
      env.SSHPASS = decrypt(t.secret_enc);
      args = ['-e', 'ssh', ...opts, '-o', 'PubkeyAuthentication=no', '-o', 'PreferredAuthentications=password,keyboard-interactive',
        `${t.ssh_user}@${t.ssh_host}`, 'sh', '-s'];
    }
    const p = spawn(cmd, args, { env });
    let stdout = '', stderr = '';
    const killer = setTimeout(() => p.kill('SIGKILL'), timeoutMs);
    p.stdout.on('data', (d) => (stdout += d));
    p.stderr.on('data', (d) => (stderr += d));
    p.on('close', (code) => {
      clearTimeout(killer);
      rmSync(dir, { recursive: true, force: true });
      resolve({ code: code ?? 1, stdout, stderr: stderr.slice(0, 2000) });
    });
    p.stdin.end(script);
  });
}

// ---- parsing ----
function section(out: string, name: string): string {
  const start = out.indexOf(`@@${name}@@`);
  if (start < 0) return '';
  const from = start + name.length + 4;
  const rest = out.slice(from);
  const next = rest.search(/@@[A-Z]+@@/);
  return (next < 0 ? rest : rest.slice(0, next)).replace(/^\n/, '');
}

function parsePackages(pkgText: string, runtimeText: string): Pkg[] {
  const out: Pkg[] = [];
  for (const line of pkgText.split('\n')) {
    const [name, version] = line.split('\t');
    if (name && version) out.push({ ecosystem: 'rpm', name: name.trim(), version: version.trim(), source: 'rpm' });
  }
  // runtime versions (php -v etc.): informational, shown and watchable even without OSV matching
  for (const line of runtimeText.split('\n')) {
    const [name, ver] = line.split('\t');
    if (!name || !ver) continue;
    const m = ver.match(/(\d+\.\d+(?:\.\d+)?)/);
    if (m) out.push({ ecosystem: 'runtime', name: name.trim(), version: m[1], source: 'cli' });
  }
  return out;
}

export function parseComposer(text: string, path: string): Pkg[] {
  try {
    const j = JSON.parse(text) as { packages?: { name: string; version: string }[]; 'packages-dev'?: { name: string; version: string }[] };
    return [...(j.packages ?? []), ...(j['packages-dev'] ?? [])]
      .filter((p) => p.name && p.version)
      .map((p) => ({ ecosystem: 'Packagist', name: p.name, version: String(p.version).replace(/^v/, ''), source: path }));
  } catch { return []; }
}
function parseNpmLock(text: string, path: string): Pkg[] {
  try {
    const j = JSON.parse(text) as { packages?: Record<string, { version?: string }> };
    const out: Pkg[] = [];
    for (const [k, v] of Object.entries(j.packages ?? {})) {
      const name = k.replace(/^.*node_modules\//, '');
      if (name && v.version) out.push({ ecosystem: 'npm', name, version: v.version, source: path });
    }
    return out;
  } catch { return []; }
}
export function parseRequirements(text: string, path: string): Pkg[] {
  const out: Pkg[] = [];
  for (const raw of text.split('\n')) {
    const line = raw.split('#')[0].trim();
    const m = line.match(/^([A-Za-z0-9._-]+)\s*==\s*([A-Za-z0-9._!+-]+)$/);
    if (m) out.push({ ecosystem: 'PyPI', name: m[1], version: m[2], source: path });
  }
  return out;
}

function parseBlocks(logsSection: string, marker: 'LOCK' | 'LOG'): { path: string; size: number; data: Buffer }[] {
  const out: { path: string; size: number; data: Buffer }[] = [];
  const re = new RegExp(`@@${marker} (.+?) (\\d+)@@\\n([\\s\\S]*?)\\n@@END${marker}@@`, 'g');
  let m: RegExpExecArray | null;
  while ((m = re.exec(logsSection))) {
    out.push({ path: m[1], size: Number(m[2]), data: Buffer.from(m[3].replace(/\s/g, ''), 'base64') });
  }
  return out;
}

export function parsePorts(text: string): { proto: 'tcp' | 'tcp6'; addr: string; port: number }[] {
  const out: { proto: 'tcp' | 'tcp6'; addr: string; port: number }[] = [];
  for (const line of text.split('\n')) {
    const m = line.match(/(\S+):(\d+)\s+\S*\s*(?:LISTEN|$)/) || line.match(/LISTEN.*?(\S+):(\d+)/);
    const addrPort = line.match(/(?:^|\s)([0-9.]+|\[[0-9a-fA-F:]+\]|\*):(\d+)\s/);
    const use = addrPort || m;
    if (!use) continue;
    const addr = use[1].replace(/^\[|\]$/g, '').replace(/^\*$/, '0.0.0.0');
    const port = Number(use[2]);
    if (port > 0 && port < 65536) out.push({ proto: addr.includes(':') ? 'tcp6' : 'tcp', addr, port });
  }
  return out;
}

export async function pollPull(hostId: string): Promise<{ ok: boolean; packages?: number; logs?: number; error?: string }> {
  const t = await q1<PullTarget>('SELECT * FROM pull_targets WHERE host_id=$1', [hostId]);
  const host = await q1<HostRow>('SELECT id, name, hostname, baseline_done, disabled, state, system_roots, allowed_ips FROM hosts WHERE id=$1', [hostId]);
  if (!t || !host) return { ok: false, error: 'not found' };
  const res = await runRemote(t, buildScript(t));
  if (res.code !== 0 && !res.stdout.includes('@@DONE@@')) {
    await q('UPDATE pull_targets SET last_poll_at=now(), last_error=$2 WHERE host_id=$1', [hostId, res.stderr || `ssh exit ${res.code}`]);
    return { ok: false, error: res.stderr || `ssh exit ${res.code}` };
  }
  const out = res.stdout;
  const osrel = Object.fromEntries(section(out, 'OSREL').split('\n').map((l) => l.match(/^([A-Z_]+)=(.*)$/)).filter(Boolean).map((m) => [m![1], m![2].replace(/^"|"$/g, '')]));
  const uname = section(out, 'OSREL').split('\n').find((l) => /\d/.test(l) && !l.includes('='))?.trim() ?? '';

  const pkgs = parsePackages(section(out, 'PKG'), section(out, 'RUNTIME'));
  for (const b of parseBlocks(section(out, 'LOCKS'), 'LOCK')) {
    const text = b.data.toString('utf8');
    if (b.path.endsWith('composer.lock')) pkgs.push(...parseComposer(text, b.path));
    else if (b.path.endsWith('package-lock.json')) pkgs.push(...parseNpmLock(text, b.path));
    else if (/requirements.*\.txt$/.test(b.path)) pkgs.push(...parseRequirements(text, b.path));
  }

  const fileHashes: Record<string, string> = {};
  for (const line of section(out, 'HASH').split('\n')) {
    const m = line.match(/^([0-9a-f]{64})\s+(.+)$/);
    if (m) fileHashes[m[2].trim()] = m[1];
  }
  const files = Object.entries(fileHashes).map(([p, h]) => ({ p, h, s: 0, m: 0 }));

  const report: Report = {
    schema: 1,
    agentVersion: 'pull-ssh',
    startedAt: new Date().toISOString(),
    durationMs: 0,
    host: {
      hostname: t.ssh_host, platform: 'linux',
      osName: osrel.NAME ?? (uname.split(' ')[0] || 'Linux'), osVersion: osrel.VERSION_ID ?? '',
      osId: osrel.ID ?? 'linux', kernel: uname, arch: uname.split(' ').pop() ?? '', uptimeSec: 0,
    },
    packages: pkgs,
    scanPaths: t.scan_paths,
    pythonEnvs: [],
    osAdvisories: null, // no package-manager advisories available without root on shared hosting
    osFixed: null,
    services: [],
    state: { ports: parsePorts(section(out, 'PORTS')), users: [], fileHashes },
    files,
    filesTruncated: false,
    errors: [],
  };
  await ingestReport(host, report);
  await q('UPDATE hosts SET needs_match=true WHERE id=$1', [hostId]);

  // logs: incremental, update per-file offsets
  const entries: LogEntry[] = [];
  const nextState: Record<string, number> = { ...t.log_state };
  for (const b of parseBlocks(section(out, 'LOGS'), 'LOG')) {
    nextState[b.path] = b.size;
    for (const line of b.data.toString('utf8').split('\n')) if (line) entries.push({ s: `file:${b.path}`, m: line.slice(0, 8192) });
  }
  let logN = 0;
  if (entries.length) {
    const r = await ingestLogs(host, { schema: 1, agentVersion: 'pull-ssh', entries, truncated: 0 });
    logN = r.lines;
  }
  await q('UPDATE pull_targets SET last_poll_at=now(), last_error=NULL, log_state=$2 WHERE host_id=$1', [hostId, JSON.stringify(nextState)]);
  return { ok: true, packages: pkgs.length, logs: logN };
}
