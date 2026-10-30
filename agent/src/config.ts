import { chmodSync, existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';

export interface AgentConfig {
  server: string; // https://soc.example.com (no trailing slash)
  hostId: string;
  hostToken: string;
  scanPaths: string[]; // directories searched for lockfiles
  skipDirs: string[]; // directory names never descended into
  autoUpdate: boolean;
  pin?: string; // run exactly this version (no auto update beyond it)
  journal: boolean; // collect journald logs
  logFiles: string[]; // plain log files to tail ("*" allowed in the last segment)
  useSudo: boolean; // read logs via `sudo -n` when the agent runs as a normal user
  pythonEnvs?: string[]; // shared Python environments to inventory (default: Anaconda/Miniconda envs)
  aide: boolean; // AIDE-style file-integrity scan (hash watched system paths each run)
  aidePaths?: string[]; // paths to hash (default: security-relevant system dirs); "*" allowed once
  aideExcludes?: string[]; // absolute sub-paths to skip during the integrity scan
}

export const DEFAULT_SKIP_DIRS = [
  'node_modules', '.git', '.svn', '.hg', '.next', 'dist', 'build', '.cache', '__pycache__',
  'venv', '.venv', 'site-packages', 'vendor', '_Archived', 'gomi', '.tmp', 'coverage',
];

export const DEFAULT_LOG_FILES = [
  '/var/log/auth.log', '/var/log/secure', '/var/log/fail2ban.log',
  '/var/log/httpd/*access_log', '/var/log/httpd/*access.log', '/var/log/apache2/*access.log', '/var/log/nginx/*access.log',
];

// AIDE-style integrity scan: the paths that matter for tamper detection (binaries, system config,
// privilege/persistence/remote-access). Run as root to read them all; unreadable files are skipped.
// Order matters: small, security-critical paths first, so they are baselined even if a budget-
// limited first scan does not reach the large binary trees.
export const DEFAULT_AIDE_PATHS = [
  '/root/.ssh', '/home/*/.ssh', '/etc', '/boot/grub2',
  '/bin', '/sbin', '/usr/bin', '/usr/sbin', '/usr/local/bin', '/usr/local/sbin',
];

// MINISOC2_HOME lets several agents (or tests) coexist on one machine.
export function minisoc2Home(): string {
  return process.env.MINISOC2_HOME || join(homedir(), '.minisoc2');
}

export function configPath(): string {
  return join(minisoc2Home(), 'config.json');
}

export function loadConfig(): AgentConfig | null {
  const p = configPath();
  if (!existsSync(p)) return null;
  const c = JSON.parse(readFileSync(p, 'utf8')) as Partial<AgentConfig>;
  if (!c.server || !c.hostId || !c.hostToken) return null;
  return {
    server: c.server,
    hostId: c.hostId,
    hostToken: c.hostToken,
    scanPaths: c.scanPaths ?? [],
    skipDirs: c.skipDirs ?? DEFAULT_SKIP_DIRS,
    autoUpdate: c.autoUpdate ?? true,
    pin: c.pin,
    journal: c.journal ?? true,
    logFiles: c.logFiles ?? DEFAULT_LOG_FILES,
    useSudo: c.useSudo ?? false,
    pythonEnvs: c.pythonEnvs,
    aide: c.aide ?? true,
    aidePaths: c.aidePaths,
    aideExcludes: c.aideExcludes,
  };
}

export function saveConfig(c: AgentConfig): void {
  mkdirSync(minisoc2Home(), { recursive: true });
  writeFileSync(configPath(), JSON.stringify(c, null, 2) + '\n', { mode: 0o600 });
  try {
    chmodSync(configPath(), 0o600); // the host token is a credential
  } catch {
    /* best effort */
  }
}
