// minisoc2 agent — run once, collect, report, exit.
import { copyFileSync, mkdirSync, realpathSync } from 'node:fs';
import { hostname } from 'node:os';
import { join } from 'node:path';
import { gzipSync } from 'node:zlib';
import { collect } from './collect/index.js';
import { collectLogs } from './collect/logs.js';
import { DEFAULT_AIDE_PATHS, DEFAULT_LOG_FILES, DEFAULT_SKIP_DIRS, loadConfig, minisoc2Home, saveConfig, type AgentConfig } from './config.js';
import { ensureCheckin, nodeBinary, scheduleInstall, scheduleIntervalHours, scheduleRemove, scheduleShow } from './schedule.js';
import { checkForUpdate, execBuild, pickBuild, type UpdateResult } from './update.js';
import type { LogBatch, LogEntry } from './types.js';
import { errMsg } from './util.js';
import { waitLoop } from './wait.js';

declare const __VERSION__: string;

// cron starts us with a minimal PATH, so dnf/rpm/journalctl in /usr/sbin may be missing.
{
  const extra = ['/usr/local/sbin', '/usr/local/bin', '/usr/sbin', '/usr/bin', '/sbin', '/bin'];
  const have = new Set((process.env.PATH ?? '').split(':'));
  process.env.PATH = [...(process.env.PATH ? [process.env.PATH] : []), ...extra.filter((d) => !have.has(d))].join(':');
}
const VERSION = __VERSION__;

const HELP = `minisoc2-agent ${VERSION}

Usage:
  minisoc2-agent install --server <url> --token <enroll-token> [--scan <dir,dir>] [--every <hours>] [--no-schedule]
      Register this host, copy the agent to ${'~/.minisoc2'}, and schedule periodic runs.
  minisoc2-agent run [--no-update] [--dry-run]
      Collect and report once (what the scheduler calls). --dry-run prints the report instead of sending.
  minisoc2-agent checkin
      Cheap poll (runs often): collect only if the server requested an on-demand collection.
  minisoc2-agent wait
      Hold a real-time control channel to the server (collect on demand within seconds). Runs as a
      resident service alongside cron; the schedule remains the fallback if the channel drops.
  minisoc2-agent send-log --source <name> [--file <path>]
      Send log lines from a file or stdin (e.g. from an application) right now.
  minisoc2-agent config [--scan <dir,dir>] [--skip <name,name>] [--auto-update on|off] [--pin <version>|--unpin]
                       [--log-files <path,glob>] [--journal on|off] [--sudo on|off] [--python-envs <dir,dir/*>]
                       [--aide on|off] [--aide-paths <dir,dir>] [--aide-excludes <dir,dir>]
  minisoc2-agent schedule install|remove|show [--every <hours>]
  minisoc2-agent version
`;

function parseArgs(argv: string[]): { cmd: string; sub?: string; opts: Record<string, string | boolean> } {
  const [cmd = 'help', ...rest] = argv;
  const opts: Record<string, string | boolean> = {};
  let sub: string | undefined;
  for (let i = 0; i < rest.length; i++) {
    const a = rest[i];
    if (a.startsWith('--')) {
      const key = a.slice(2);
      const next = rest[i + 1];
      if (next !== undefined && !next.startsWith('--')) {
        opts[key] = next;
        i++;
      } else opts[key] = true;
    } else if (!sub) sub = a;
  }
  return { cmd, sub, opts };
}

const list = (v: string | boolean | undefined) => (typeof v === 'string' ? v.split(',').map((s) => s.trim()).filter(Boolean) : undefined);

function requireConfig(): AgentConfig {
  const cfg = loadConfig();
  if (!cfg) {
    console.error(`not enrolled: run "minisoc2-agent install --server <url> --token <token>" first`);
    process.exit(2);
  }
  return cfg;
}

async function postJson(url: string, body: unknown, token?: string): Promise<Response> {
  const gz = gzipSync(Buffer.from(JSON.stringify(body)));
  return fetch(url, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      'content-encoding': 'gzip',
      ...(token ? { authorization: `Bearer ${token}` } : {}),
    },
    body: gz,
  });
}

async function install(opts: Record<string, string | boolean>) {
  const server = String(opts.server ?? '').replace(/\/+$/, '');
  const token = String(opts.token ?? '');
  if (!/^https?:\/\//.test(server) || !token) {
    console.error('install needs --server <url> and --token <enroll-token>');
    process.exit(2);
  }
  const res = await postJson(`${server}/api/v1/enroll`, { token, hostname: hostname(), platform: process.platform, agentVersion: VERSION });
  const j = (await res.json().catch(() => ({}))) as { hostId?: string; hostToken?: string; error?: string };
  if (!res.ok || !j.hostId || !j.hostToken) {
    console.error(`enroll failed: HTTP ${res.status} ${j.error ?? ''}`);
    process.exit(1);
  }
  const prev = loadConfig();
  saveConfig({
    server,
    hostId: j.hostId,
    hostToken: j.hostToken,
    scanPaths: list(opts.scan) ?? prev?.scanPaths ?? [],
    skipDirs: prev?.skipDirs ?? DEFAULT_SKIP_DIRS,
    autoUpdate: prev?.autoUpdate ?? true,
    pin: prev?.pin,
    journal: prev?.journal ?? true,
    logFiles: prev?.logFiles ?? DEFAULT_LOG_FILES,
    useSudo: opts.sudo !== undefined ? opts.sudo !== 'off' : prev?.useSudo ?? false,
    aide: opts.aide !== undefined ? opts.aide !== 'off' : prev?.aide ?? true,
    aidePaths: prev?.aidePaths,
    aideExcludes: prev?.aideExcludes,
  });
  // Copy this build to a stable path so the scheduler does not depend on the npx cache.
  mkdirSync(minisoc2Home(), { recursive: true });
  const target = join(minisoc2Home(), 'minisoc2.mjs');
  const self = realpathSync(process.argv[1]);
  if (self !== target) copyFileSync(self, target);
  console.log(`enrolled as ${j.hostId}; agent copied to ${target}`);
  if (!opts['no-schedule']) await scheduleInstall(target, Number(opts.every ?? 1));
  console.log('running a first report...');
  await runOnce({ 'no-update': true });
}

// Cheap check-in for on-demand collection: ask the server if a collection was requested; if so, run
// a full report. Called frequently by cron, so it does almost nothing in the common (no-request) case.
async function pendingCheck(cfg: AgentConfig): Promise<boolean> {
  try {
    const res = await fetch(`${cfg.server}/api/v1/pending`, { headers: { authorization: `Bearer ${cfg.hostToken}` } });
    if (!res.ok) return false;
    const j = (await res.json().catch(() => ({}))) as { collect?: boolean };
    return !!j.collect;
  } catch {
    return false;
  }
}

async function checkin() {
  const cfg = requireConfig();
  if (await pendingCheck(cfg)) {
    console.log('on-demand collection requested');
    await runOnce({});
  }
}

async function runOnce(opts: Record<string, string | boolean>) {
  const cfg = requireConfig();
  let update: UpdateResult = process.env.MINISOC2_UPDATE_INFO ? JSON.parse(process.env.MINISOC2_UPDATE_INFO) : { checked: false };
  if (cfg.autoUpdate && !opts['no-update'] && !process.env.MINISOC2_NO_UPDATE) {
    update = await checkForUpdate(cfg, VERSION);
    const next = pickBuild(cfg, VERSION);
    if (next) execBuild(next, process.argv.slice(2), update);
  }
  const report = await collect(cfg, VERSION);
  report.update = update;
  report.config = {
    scanPaths: cfg.scanPaths, skipDirs: cfg.skipDirs, aidePaths: cfg.aidePaths ?? DEFAULT_AIDE_PATHS, aideExcludes: cfg.aideExcludes ?? [],
    logFiles: cfg.logFiles, journal: cfg.journal, useSudo: cfg.useSudo, autoUpdate: cfg.autoUpdate, aide: cfg.aide, pin: cfg.pin,
  };
  const target = join(minisoc2Home(), 'minisoc2.mjs');
  report.agent = { invoke: `"${nodeBinary()}" "${target}"`, root: process.getuid?.() === 0, home: minisoc2Home(), intervalHours: await scheduleIntervalHours() };
  if (opts['dry-run']) {
    console.log(JSON.stringify(report, null, 2));
    return;
  }
  const res = await postJson(`${cfg.server}/api/v1/report`, report, cfg.hostToken);
  const j = (await res.json().catch(() => ({}))) as Record<string, unknown>;
  if (!res.ok) {
    console.error(`report failed: HTTP ${res.status} ${JSON.stringify(j)}`);
    process.exit(1);
  }
  console.log(`reported: ${report.packages.length} packages, ${report.osAdvisories?.length ?? 'n/a'} os advisories, ${report.errors.length} errors in ${report.durationMs}ms`);
  for (const e of report.errors) console.log(`  ! ${e.step}: ${e.message}`);

  const logErrors: { step: string; message: string }[] = [];
  const logs = await collectLogs(cfg, logErrors);
  for (const e of logErrors) console.log(`  ! ${e.step}: ${e.message}`);
  if (logs.entries.length) {
    await sendLogs(cfg, logs.entries, logs.truncated);
    console.log(`logs: ${logs.entries.length} lines (${Math.round(logs.bytes / 1024)} KiB)${logs.truncated ? ', truncated at the per-run limit' : ''}`);
  }
  logs.commit();
  // self-heal: ensure the frequent check-in cron exists (hosts updated from an older build get it)
  await ensureCheckin(join(minisoc2Home(), 'minisoc2.mjs'));
}

// Uploads in chunks; throws on the first failure so the caller does not commit log positions.
async function sendLogs(cfg: AgentConfig, entries: LogEntry[], truncated: number) {
  const CHUNK = 20_000;
  for (let i = 0; i < entries.length; i += CHUNK) {
    const batch: LogBatch = { schema: 1, agentVersion: VERSION, entries: entries.slice(i, i + CHUNK), truncated: i === 0 ? truncated : 0 };
    const res = await postJson(`${cfg.server}/api/v1/logs`, batch, cfg.hostToken);
    if (!res.ok) throw new Error(`log upload failed: HTTP ${res.status} ${await res.text().catch(() => '')}`.slice(0, 300));
  }
}

async function sendLog(opts: Record<string, string | boolean>) {
  const cfg = requireConfig();
  const source = typeof opts.source === 'string' ? opts.source.replace(/[^\w.:/-]/g, '_').slice(0, 100) : '';
  if (!source) {
    console.error('send-log needs --source <name>');
    process.exit(2);
  }
  let text: string;
  if (typeof opts.file === 'string') text = (await import('node:fs')).readFileSync(opts.file, 'utf8');
  else {
    const chunks: Buffer[] = [];
    for await (const c of process.stdin) chunks.push(c as Buffer);
    text = Buffer.concat(chunks).toString('utf8');
  }
  const entries = text.split(/\r?\n/).filter(Boolean).map((m) => ({ s: `app:${source}`, m: m.slice(0, 8192) }));
  if (!entries.length) return;
  await sendLogs(cfg, entries, 0);
  console.log(`sent ${entries.length} lines as app:${source}`);
}

function configure(opts: Record<string, string | boolean>) {
  const cfg = requireConfig();
  if (opts.scan !== undefined) cfg.scanPaths = list(opts.scan) ?? [];
  if (opts.skip !== undefined) cfg.skipDirs = list(opts.skip) ?? [];
  if (opts['auto-update'] !== undefined) cfg.autoUpdate = opts['auto-update'] !== 'off';
  if (typeof opts.pin === 'string') cfg.pin = opts.pin;
  if (opts.unpin) delete cfg.pin;
  if (opts['log-files'] !== undefined) cfg.logFiles = list(opts['log-files']) ?? [];
  if (opts.journal !== undefined) cfg.journal = opts.journal !== 'off';
  if (opts.sudo !== undefined) cfg.useSudo = opts.sudo !== 'off';
  if (opts['python-envs'] !== undefined) cfg.pythonEnvs = list(opts['python-envs']) ?? [];
  if (opts.aide !== undefined) cfg.aide = opts.aide !== 'off';
  if (opts['aide-paths'] !== undefined) cfg.aidePaths = list(opts['aide-paths']);
  if (opts['aide-excludes'] !== undefined) cfg.aideExcludes = list(opts['aide-excludes']);
  saveConfig(cfg);
  const { hostToken: _t, ...shown } = cfg;
  console.log(JSON.stringify(shown, null, 2));
}

async function main() {
  const { cmd, sub, opts } = parseArgs(process.argv.slice(2));
  // Every command (not only run) uses the newest build already downloaded, so config/schedule
  // understand options added after the stable copy in ~/.minisoc2 was installed.
  const cfg0 = cmd !== 'install' && !process.env.MINISOC2_NO_UPDATE ? loadConfig() : null;
  if (cfg0) {
    const newer = pickBuild(cfg0, VERSION);
    if (newer) execBuild(newer, process.argv.slice(2), { checked: false });
  }
  switch (cmd) {
    case 'install':
      return install(opts);
    case 'run':
      return runOnce(opts);
    case 'checkin':
      return checkin();
    case 'wait':
      return waitLoop(requireConfig(), VERSION);
    case 'config':
      return configure(opts);
    case 'send-log':
      return sendLog(opts);
    case 'schedule': {
      const target = join(minisoc2Home(), 'minisoc2.mjs');
      if (sub === 'install') return scheduleInstall(target, Number(opts.every ?? 1));
      if (sub === 'remove') return scheduleRemove();
      return scheduleShow();
    }
    case 'version':
    case '--version':
      console.log(VERSION);
      return;
    default:
      console.log(HELP);
  }
}

main().catch((e) => {
  console.error(`minisoc2-agent: ${errMsg(e)}`);
  process.exit(1);
});
