// Register periodic runs with the OS scheduler: crontab (Linux).
import { spawnSync } from 'node:child_process';
import { existsSync, realpathSync } from 'node:fs';
import { delimiter, join } from 'node:path';
import { minisoc2Home } from './config.js';
import { run } from './util.js';

const MARK = '# minisoc2-agent';

// Prefer a stable "node" on PATH that points at the running binary (e.g. /usr/bin/node rather than
// /usr/bin/node-24) so the schedule survives Node.js upgrades.
export function nodeBinary(): string {
  const self = realpathSync(process.execPath);
  for (const dir of (process.env.PATH ?? '').split(delimiter)) {
    const cand = join(dir, 'node');
    try {
      if (existsSync(cand) && realpathSync(cand) === self) return cand;
    } catch {
      /* ignore */
    }
  }
  return process.execPath;
}

function cronLine(target: string, hours: number): string {
  const minute = Math.floor(Math.random() * 60); // spread load across hosts
  const h = Math.max(1, Math.min(24, Math.round(hours)));
  const hourField = h >= 24 ? String(Math.floor(Math.random() * 24)) : `*/${h}`;
  const log = join(minisoc2Home(), 'agent.log');
  const env = process.env.MINISOC2_HOME ? `MINISOC2_HOME="${process.env.MINISOC2_HOME}" ` : '';
  return `${minute} ${hourField} * * * ${env}"${nodeBinary()}" "${target}" run >> "${log}" 2>&1 ${MARK}`;
}

async function readCrontab(): Promise<string> {
  const r = await run('crontab', ['-l'], 10_000);
  return r.ok ? r.stdout : '';
}

function writeCrontab(text: string): void {
  const r = spawnSync('crontab', ['-'], { input: text });
  if (r.status !== 0) throw new Error(`crontab write failed: ${String(r.stderr)}`);
}

export async function scheduleInstall(target: string, hours: number): Promise<void> {
  const kept = (await readCrontab()).split('\n').filter((l) => l && !l.includes(MARK));
  const line = cronLine(target, hours);
  writeCrontab([...kept, line].join('\n') + '\n');
  console.log(`scheduled (crontab): ${line}`);
}

export async function scheduleRemove(): Promise<void> {
  const kept = (await readCrontab()).split('\n').filter((l) => l && !l.includes(MARK));
  writeCrontab(kept.length ? kept.join('\n') + '\n' : '');
  console.log('removed minisoc2-agent from crontab');
}

export async function scheduleShow(): Promise<void> {
  const line = (await readCrontab()).split('\n').find((l) => l.includes(MARK));
  console.log(line ?? 'not scheduled');
}

// The current collection interval in hours, parsed from the crontab line ("*/N ..." or a fixed hour).
export async function scheduleIntervalHours(): Promise<number | undefined> {
  const line = (await readCrontab()).split('\n').find((l) => l.includes(MARK));
  if (!line) return undefined;
  const hourField = line.trim().split(/\s+/)[1] ?? '';
  const m = hourField.match(/^\*\/(\d+)$/);
  if (m) return Number(m[1]);
  return /^\d+$/.test(hourField) ? 24 : undefined;
}
