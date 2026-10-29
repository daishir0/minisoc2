// Minimal .env reader shared by the maintenance scripts (no dependency on dotenv).
import { existsSync, readFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

export const repoRoot = join(dirname(fileURLToPath(import.meta.url)), '..');

export function loadEnv(file = join(repoRoot, 'server/.env')) {
  const env = {};
  if (existsSync(file)) {
    for (const line of readFileSync(file, 'utf8').split('\n')) {
      const m = line.match(/^\s*([A-Z0-9_]+)\s*=\s*(.*)\s*$/);
      if (m) env[m[1]] = m[2].replace(/^["']|["']$/g, '');
    }
  }
  return { ...env, ...process.env };
}

export function signingKeyPath(env) {
  const p = env.SIGNING_KEY_PATH || join(homedir(), '.config/minisoc2/signing.key');
  return p.replace(/^~(?=\/)/, homedir());
}

export function agentDistDir(env) {
  const p = env.AGENT_DIST_DIR || join(repoRoot, 'server/data/agent');
  return p.startsWith('/') ? p : join(repoRoot, 'server', p);
}
