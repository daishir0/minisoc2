// Register periodic runs with the OS scheduler: crontab (Linux).
import { spawnSync } from 'node:child_process';
import { existsSync, realpathSync } from 'node:fs';
import { delimiter, join } from 'node:path';
import { minisoc2Home } from './config.js';
import { run } from './util.js';

const MARK = '# minisoc2-agent';
const CHECKIN_MARK = '# minisoc2-agent-checkin';
const CHECKIN_MIN = 5; // lightweight check-in cadence (minutes) for on-demand collection

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

function checkinLine(target: string): string {
  const log = join(minisoc2Home(), 'agent.log');
  const env = process.env.MINISOC2_HOME ? `MINISOC2_HOME="${process.env.MINISOC2_HOME}" ` : '';
  return `*/${CHECKIN_MIN} * * * * ${env}"${nodeBinary()}" "${target}" checkin >> "${log}" 2>&1 ${CHECKIN_MARK}`;
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
  const kept = (await readCrontab()).split('\n').filter((l) => l && !l.includes(MARK) && !l.includes(CHECKIN_MARK));
  const line = cronLine(target, hours);
  const chk = checkinLine(target);
  writeCrontab([...kept, line, chk].join('\n') + '\n');
  console.log(`scheduled (crontab): ${line}`);
  console.log(`scheduled (crontab): ${chk}`);
}

export async function scheduleRemove(): Promise<void> {
  const kept = (await readCrontab()).split('\n').filter((l) => l && !l.includes(MARK) && !l.includes(CHECKIN_MARK));
  writeCrontab(kept.length ? kept.join('\n') + '\n' : '');
  console.log('removed minisoc2-agent from crontab');
}

// Add the check-in cron if it is missing (self-heal, so hosts updated from an older build get it).
export async function ensureCheckin(target: string): Promise<void> {
  const cur = await readCrontab();
  if (cur.split('\n').some((l) => l.includes(CHECKIN_MARK))) return;
  const kept = cur.split('\n').filter(Boolean);
  try {
    writeCrontab([...kept, checkinLine(target)].join('\n') + '\n');
  } catch {
    /* best effort */
  }
}

export async function scheduleShow(): Promise<void> {
  const lines = (await readCrontab()).split('\n').filter((l) => l.includes(MARK) || l.includes(CHECKIN_MARK));
  console.log(lines.length ? lines.join('\n') : 'not scheduled');
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
