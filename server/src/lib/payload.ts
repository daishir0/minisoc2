// Payload received from the agent (POST /api/v1/report, /api/v1/logs).
// Copied from agent/src/types.ts — keep both in sync.

export interface HostInfo {
  hostname: string;
  platform: NodeJS.Platform;
  osName: string; // e.g. "Amazon Linux", "Ubuntu", "Debian"
  osVersion: string; // e.g. "2023", "22.04"
  osId: string; // /etc/os-release ID (amzn, ubuntu, debian, alpine, rhel ...)
  kernel: string;
  arch: string;
  uptimeSec: number;
}

// One installed package. ecosystem follows OSV naming where possible
// (npm, PyPI, Packagist, Debian:12, Ubuntu:22.04:LTS, Alpine:v3.19) or "rpm".
export interface Pkg {
  ecosystem: string;
  name: string;
  version: string;
  source: string; // where it was found: "rpm", "dpkg", or the lockfile path
}

// A pending security update reported by the OS package manager itself
// (dnf updateinfo on RPM distros). One row per CVE x package.
export interface OsAdvisory {
  id: string; // CVE-xxxx-yyyy (or advisory id when no CVE)
  advisory?: string; // ALAS2023-2026-1611
  severity: string; // critical | high | medium | low | unknown
  pkg: string; // package name
  fixed: string; // version that fixes it
}

export interface ListenPort {
  proto: 'tcp' | 'tcp6' | 'udp' | 'udp6';
  addr: string;
  port: number;
}

export interface HostState {
  ports: ListenPort[];
  users: string[]; // login-capable accounts
  fileHashes: Record<string, string>; // path -> sha256 (authorized_keys, sudoers, crontab ...)
}

export interface ServiceInfo {
  name: string; // nginx.service
  cwd: string;
  exec: string; // ExecStart path
  argv: string;
  user: string;
  bin: string; // interpreter / executable as configured (venv paths stay intact)
  realBin?: string; // symlinks resolved
  condaEnv?: string; // from "activate <env>"
  execPkg?: string; // OS package that owns bin
}

// One file in the integrity (AIDE-style) scan: path, sha256, size, mtime (epoch ms).
export interface FileHash {
  p: string;
  h: string;
  s: number;
  m: number;
}

export interface CollectError {
  step: string;
  message: string;
}

export interface Report {
  schema: 1;
  agentVersion: string;
  startedAt: string;
  durationMs: number;
  host: HostInfo;
  packages: Pkg[];
  scanPaths?: string[]; // roots searched for lockfiles (the server derives systems from them)
  pythonEnvs?: string[]; // shared Python environments that were inventoried (each becomes a system)
  osAdvisories: OsAdvisory[] | null; // null = not supported on this OS
  osFixed?: OsAdvisory[] | null; // security advisories already applied (evidence for "not affected")
  services?: ServiceInfo[]; // running services (links applications to runtimes and OS packages)
  state: HostState;
  files?: FileHash[] | null; // AIDE-style file-integrity scan (null = not collected this run)
  filesTruncated?: boolean;
  errors: CollectError[];
  update?: { checked: boolean; latest?: string; error?: string };
}

// One log line (POST /api/v1/logs). s = source ("journal:sshd.service", "file:/var/log/secure", "app:myapp").
export interface LogEntry {
  s: string;
  t?: string; // ISO time when known
  m: string;
}

export interface LogBatch {
  schema: 1;
  agentVersion: string;
  entries: LogEntry[];
  truncated: number;
}
