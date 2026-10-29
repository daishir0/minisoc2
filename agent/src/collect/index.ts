import { arch, hostname, release, uptime } from 'node:os';
import type { AgentConfig } from '../config.js';
import type { CollectError, HostInfo, HostState, Report } from '../types.js';
import { errMsg, readText, run, sha256 } from '../util.js';
import { DEFAULT_PYTHON_ENVS, collectDeps, expandEnvs } from './deps.js';
import { linuxServices } from './services.js';
import { dnfAdvisories, dnfFixed, linuxPackages, linuxPorts, linuxUsers, linuxWatchedFiles, osRelease } from './linux.js';
import { fileIntegrity } from './integrity.js';
import { DEFAULT_AIDE_PATHS } from '../config.js';

function hostInfo(): HostInfo {
  const base = { hostname: hostname(), platform: process.platform, kernel: release(), arch: arch(), uptimeSec: Math.round(uptime()) };
  const rel = osRelease();
  return { ...base, osName: rel.NAME ?? 'Linux', osVersion: rel.VERSION_ID ?? '', osId: rel.ID ?? 'linux' };
}

async function hostState(): Promise<HostState> {
  const state: HostState = { ports: [], users: [], fileHashes: {} };
  state.ports = linuxPorts();
  state.users = linuxUsers();
  for (const f of linuxWatchedFiles()) {
    const t = readText(f);
    if (t != null) state.fileHashes[f] = sha256(t);
  }
  const cron = await run('crontab', ['-l'], 10_000);
  if (cron.ok) state.fileHashes['crontab -l'] = sha256(cron.stdout);
  return state;
}

export async function collect(cfg: AgentConfig, agentVersion: string): Promise<Report> {
  const started = Date.now();
  const errors: CollectError[] = [];
  const step = async <T>(name: string, fn: () => Promise<T> | T, fallback: T): Promise<T> => {
    try {
      return await fn();
    } catch (e) {
      errors.push({ step: name, message: errMsg(e) });
      return fallback;
    }
  };

  const [osPkgs, osAdvisories, state] = await Promise.all([
    step('packages', () => linuxPackages(errors), []),
    step('osAdvisories', () => dnfAdvisories(errors, cfg.useSudo), null),
    step('state', () => hostState(), { ports: [], users: [], fileHashes: {} }),
  ]);
  const appPkgs = await step('deps', () => collectDeps(cfg.scanPaths, cfg.skipDirs, errors, cfg.pythonEnvs), []);
  const osFixed = await step('osFixed', () => dnfFixed(errors, cfg.useSudo), null);
  const services = await step('services', () => linuxServices(errors), []);
  const integrity = cfg.aide
    ? await step('files', () => fileIntegrity({ ...cfg, aidePaths: cfg.aidePaths ?? DEFAULT_AIDE_PATHS }, errors), { files: [], truncated: false })
    : { files: null as never, truncated: false };

  return {
    schema: 1,
    agentVersion,
    startedAt: new Date(started).toISOString(),
    durationMs: Date.now() - started,
    host: hostInfo(),
    packages: [...osPkgs, ...appPkgs],
    scanPaths: cfg.scanPaths,
    pythonEnvs: expandEnvs(cfg.pythonEnvs ?? DEFAULT_PYTHON_ENVS),
    osAdvisories,
    osFixed,
    services,
    state,
    files: cfg.aide ? integrity.files : null,
    filesTruncated: integrity.truncated,
    errors,
  };
}
