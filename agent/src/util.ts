import { execFile } from 'node:child_process';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';

export interface ExecResult {
  ok: boolean;
  stdout: string;
  stderr: string;
  code: number | null;
}

// Run a command without a shell. Never throws: missing binaries and
// non-zero exits come back as ok=false so collectors can degrade gracefully.
const DEBUG = !!process.env.MINISOC2_DEBUG;

export function debug(msg: string): void {
  if (DEBUG) process.stderr.write(`[minisoc2 ${new Date().toISOString()}] ${msg}\n`);
}

export function run(cmd: string, args: string[], timeoutMs = 120_000): Promise<ExecResult> {
  const started = Date.now();
  debug(`exec ${cmd} ${args.join(' ').slice(0, 120)}`);
  return new Promise((resolve) => {
    execFile(cmd, args, { timeout: timeoutMs, maxBuffer: 256 * 1024 * 1024 }, (err, stdout, stderr) => {
      debug(`done ${cmd} in ${Date.now() - started}ms${err ? ` (error: ${String((err as Error).message).slice(0, 80)})` : ''}`);
      const code = err && typeof (err as NodeJS.ErrnoException).code === 'number' ? Number((err as NodeJS.ErrnoException).code) : err ? null : 0;
      resolve({ ok: !err, stdout: String(stdout ?? ''), stderr: String(stderr ?? ''), code });
    });
  });
}

export function sha256(data: string | Buffer): string {
  return createHash('sha256').update(data).digest('hex');
}

export function readText(path: string): string | null {
  try {
    return readFileSync(path, 'utf8');
  } catch {
    return null;
  }
}

export function errMsg(e: unknown): string {
  return e instanceof Error ? e.message : String(e);
}

// Compare dotted versions numerically ("0.10.0" > "0.9.3").
export function cmpVersion(a: string, b: string): number {
  const pa = a.split(/[.+-]/).map((x) => parseInt(x, 10) || 0);
  const pb = b.split(/[.+-]/).map((x) => parseInt(x, 10) || 0);
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    const d = (pa[i] ?? 0) - (pb[i] ?? 0);
    if (d) return d;
  }
  return 0;
}
