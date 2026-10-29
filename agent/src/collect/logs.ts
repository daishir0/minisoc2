// Incremental log collection: journald (cursor) and plain log files (inode + offset).
// The new position is committed only after the server has accepted every batch,
// so a failed upload is retried on the next run instead of losing lines.
import { readdirSync, readFileSync, writeFileSync } from 'node:fs';
import { basename, dirname, join } from 'node:path';
import { minisoc2Home, type AgentConfig } from '../config.js';
import type { CollectError, LogEntry } from '../types.js';
import { run } from '../util.js';

const MAX_BYTES_PER_RUN = 64 * 1024 * 1024;
const FIRST_READ_TAIL = 8 * 1024 * 1024; // a newly seen file is read from its last 8 MB
const MAX_LINE = 8192;

interface LogState {
  journalCursor?: string;
  files: Record<string, { ino: string; offset: number }>;
}

function statePath(): string {
  return join(minisoc2Home(), 'logstate.json');
}

function loadState(): LogState {
  try {
    return { files: {}, ...JSON.parse(readFileSync(statePath(), 'utf8')) };
  } catch {
    return { files: {} };
  }
}

// Minimal glob: "*" is allowed in the last path segment only. Directories such as /var/log/httpd
// are often root-only, so they are listed through sudo when enabled.
async function expand(cfg: AgentConfig, pattern: string): Promise<string[]> {
  if (!pattern.includes('*')) return [pattern];
  const dir = dirname(pattern);
  const re = new RegExp('^' + basename(pattern).replace(/[.+^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*') + '$');
  let names: string[];
  try {
    names = readdirSync(dir);
  } catch {
    if (!cfg.useSudo) return [];
    const r = await run('sudo', ['-n', 'ls', '-1', dir], 30_000);
    names = r.ok ? r.stdout.split('\n').filter(Boolean) : [];
  }
  return names.filter((f) => re.test(f)).map((f) => join(dir, f));
}

const sudo = (cfg: AgentConfig, cmd: string, args: string[]) => (cfg.useSudo ? run('sudo', ['-n', cmd, ...args], 300_000) : run(cmd, args, 300_000));

export interface LogCollection {
  entries: LogEntry[];
  bytes: number;
  truncated: number;
  commit: () => void;
}

async function collectJournal(cfg: AgentConfig, st: LogState, next: LogState, out: LogEntry[], budget: { bytes: number }, errors: CollectError[]) {
  const args = ['-o', 'json', '--no-pager', '-q', '--output-fields=MESSAGE,_SYSTEMD_UNIT,SYSLOG_IDENTIFIER,__REALTIME_TIMESTAMP'];
  if (st.journalCursor) args.push(`--after-cursor=${st.journalCursor}`);
  else args.push('--since=-24h');
  const r = await sudo(cfg, 'journalctl', args);
  if (!r.ok && !r.stdout) {
    if (r.stderr && !/No such file|not found/i.test(r.stderr)) errors.push({ step: 'logs', message: `journalctl: ${r.stderr.slice(0, 300)}` });
    return;
  }
  for (const line of r.stdout.split('\n')) {
    if (!line) continue;
    if (budget.bytes <= 0) break;
    let j: Record<string, unknown>;
    try {
      j = JSON.parse(line);
    } catch {
      continue;
    }
    // MESSAGE may be a byte array for non-UTF-8 data
    const raw = j.MESSAGE;
    const msg = typeof raw === 'string' ? raw : Array.isArray(raw) ? Buffer.from(raw as number[]).toString('utf8') : '';
    const unit = String(j._SYSTEMD_UNIT ?? j.SYSLOG_IDENTIFIER ?? 'unknown');
    const us = Number(j.__REALTIME_TIMESTAMP);
    const ident = j.SYSLOG_IDENTIFIER ? `${j.SYSLOG_IDENTIFIER}: ` : '';
    const m = (ident + msg).slice(0, MAX_LINE);
    out.push({ s: `journal:${unit}`, t: Number.isFinite(us) ? new Date(us / 1000).toISOString() : undefined, m });
    budget.bytes -= m.length;
    next.journalCursor = String(j.__CURSOR ?? next.journalCursor ?? '');
  }
}

async function collectFile(cfg: AgentConfig, path: string, st: LogState, next: LogState, out: LogEntry[], budget: { bytes: number }) {
  const s = await sudo(cfg, 'stat', ['-c', '%i %s', path]);
  if (!s.ok) return; // missing or unreadable: silently skipped (many defaults will not exist)
  const [ino, sizeStr] = s.stdout.trim().split(' ');
  const size = Number(sizeStr);
  const prev = st.files[path];
  let offset = prev && prev.ino === ino && prev.offset <= size ? prev.offset : prev ? 0 : Math.max(0, size - FIRST_READ_TAIL);
  if (offset >= size) {
    next.files[path] = { ino, offset: size };
    return;
  }
  const want = Math.min(size - offset, budget.bytes);
  if (want <= 0) return;
  const r = await sudo(cfg, 'tail', ['-c', `+${offset + 1}`, path]);
  if (!r.ok) return;
  let chunk = r.stdout.slice(0, want);
  // only consume whole lines; a partial last line is read next time
  const lastNl = chunk.lastIndexOf('\n');
  if (lastNl < 0) return;
  chunk = chunk.slice(0, lastNl + 1);
  if (!prev && offset > 0) chunk = chunk.slice(chunk.indexOf('\n') + 1); // drop the cut first line
  for (const line of chunk.split('\n')) if (line) out.push({ s: `file:${path}`, m: line.slice(0, MAX_LINE) });
  offset += Buffer.byteLength(r.stdout.slice(0, lastNl + 1));
  budget.bytes -= chunk.length;
  next.files[path] = { ino, offset };
}

export async function collectLogs(cfg: AgentConfig, errors: CollectError[]): Promise<LogCollection> {
  const st = loadState();
  const next: LogState = { ...st, files: { ...st.files } };
  const entries: LogEntry[] = [];
  const budget = { bytes: MAX_BYTES_PER_RUN };
  if (cfg.journal) await collectJournal(cfg, st, next, entries, budget, errors);
  for (const pattern of cfg.logFiles) {
    for (const path of await expand(cfg, pattern)) await collectFile(cfg, path, st, next, entries, budget);
  }
  const bytes = MAX_BYTES_PER_RUN - budget.bytes;
  return {
    entries,
    bytes,
    truncated: budget.bytes <= 0 ? 1 : 0,
    commit: () => writeFileSync(statePath(), JSON.stringify(next) + '\n', { mode: 0o600 }),
  };
}
