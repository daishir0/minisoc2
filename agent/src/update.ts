// Self-update: fetch the server's signed manifest, download a newer build if any,
// verify sha256 + ed25519 signature, then re-exec the newest local build.
// Any failure falls back to the newest build already on disk (best effort, never blocks a run).
import { spawnSync } from 'node:child_process';
import { verify } from 'node:crypto';
import { existsSync, mkdirSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { minisoc2Home, type AgentConfig } from './config.js';
import { cmpVersion, errMsg, sha256 } from './util.js';

declare const __PUBKEY__: string;

interface ManifestEntry {
  file: string;
  sha256: string;
  signature: string; // base64 ed25519 over `${version}\n${sha256}`
}
interface Manifest {
  latest: string;
  versions: Record<string, ManifestEntry>;
}

export interface UpdateResult {
  checked: boolean;
  latest?: string;
  error?: string;
}

function versionsDir(): string {
  return join(minisoc2Home(), 'versions');
}

function localVersions(): string[] {
  try {
    return readdirSync(versionsDir())
      .filter((v) => /^\d+\.\d+\.\d+/.test(v) && existsSync(join(versionsDir(), v, 'minisoc2.mjs')))
      .sort(cmpVersion);
  } catch {
    return [];
  }
}

export function verifyBuild(version: string, body: Buffer, entry: ManifestEntry): string | null {
  const digest = sha256(body);
  if (digest !== entry.sha256) return `sha256 mismatch for ${version}`;
  if (!__PUBKEY__) return 'this build has no embedded signing key';
  const ok = verify(null, Buffer.from(`${version}\n${digest}`), __PUBKEY__, Buffer.from(entry.signature, 'base64'));
  return ok ? null : `bad signature for ${version}`;
}

async function fetchWithTimeout(url: string, ms: number): Promise<Response> {
  const ac = new AbortController();
  const t = setTimeout(() => ac.abort(), ms);
  try {
    return await fetch(url, { signal: ac.signal });
  } finally {
    clearTimeout(t);
  }
}

export async function checkForUpdate(cfg: AgentConfig, self: string): Promise<UpdateResult> {
  try {
    const res = await fetchWithTimeout(`${cfg.server}/agent/manifest.json`, 15_000);
    if (!res.ok) return { checked: false, error: `manifest HTTP ${res.status}` };
    const m = (await res.json()) as Manifest;
    const target = cfg.pin ?? m.latest;
    const entry = m.versions?.[target];
    if (!entry) return { checked: true, latest: m.latest, error: cfg.pin ? `pinned version ${cfg.pin} not on server` : undefined };
    const wanted = cfg.pin ? target !== self : cmpVersion(target, self) > 0;
    if (!wanted || localVersions().includes(target)) return { checked: true, latest: m.latest };

    const bin = await fetchWithTimeout(`${cfg.server}/agent/${entry.file}`, 60_000);
    if (!bin.ok) return { checked: true, latest: m.latest, error: `download HTTP ${bin.status}` };
    const body = Buffer.from(await bin.arrayBuffer());
    const bad = verifyBuild(target, body, entry);
    if (bad) return { checked: true, latest: m.latest, error: bad };

    const dir = join(versionsDir(), target);
    mkdirSync(dir, { recursive: true });
    writeFileSync(join(dir, 'minisoc2.mjs'), body, { mode: 0o755 });
    // keep the three newest builds as fallbacks
    const all = localVersions();
    for (const old of all.slice(0, Math.max(0, all.length - 3))) {
      if (old !== cfg.pin) rmSync(join(versionsDir(), old), { recursive: true, force: true });
    }
    return { checked: true, latest: m.latest };
  } catch (e) {
    return { checked: false, error: errMsg(e) };
  }
}

// Returns the path of a build that should run instead of this one, or null to continue here.
export function pickBuild(cfg: AgentConfig, self: string): string | null {
  const local = localVersions();
  let best: string | undefined;
  if (cfg.pin) best = local.includes(cfg.pin) ? cfg.pin : undefined;
  else best = local.filter((v) => cmpVersion(v, self) > 0).pop();
  if (!best || best === self) return null;
  return join(versionsDir(), best, 'minisoc2.mjs');
}

// checked=true: this run already asked the server, so the child must not ask again.
// checked=false: we only hand over to a newer local build, which still checks for updates itself.
export function execBuild(path: string, args: string[], update: UpdateResult): never {
  const env: NodeJS.ProcessEnv = { ...process.env, MINISOC2_UPDATE_INFO: JSON.stringify(update) };
  if (update.checked) env.MINISOC2_NO_UPDATE = '1';
  else delete env.MINISOC2_NO_UPDATE;
  const r = spawnSync(process.execPath, [path, ...args], { stdio: 'inherit', env });
  process.exit(r.status ?? 1);
}
