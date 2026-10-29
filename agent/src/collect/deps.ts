// Application dependency inventory from lockfiles (no package manager needed).
import { existsSync, readdirSync, statSync } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';
import type { CollectError, Pkg } from '../types.js';
import { debug, errMsg, readText } from '../util.js';

const LOCKFILES = new Set(['package-lock.json', 'composer.lock']);
const MAX_FILES = 5000;

function isRequirements(name: string): boolean {
  return /^requirements.*\.txt$/i.test(name);
}

const MAX_SCAN_MS = 120_000;
const MAX_DIRS = 200_000;

// Installed Python distributions in one site-packages directory (what actually runs, unlike
// unpinned requirements.txt). Source paths keep the env root so the server can attribute them.
export function sitePackages(env: string): Pkg[] {
  const out: Pkg[] = [];
  let libs: string[] = [];
  try {
    libs = readdirSync(join(env, 'lib')).filter((d) => /^python\d/.test(d)).map((d) => join(env, 'lib', d, 'site-packages'));
  } catch {
    /* no lib dir */
  }
  for (const sp of libs) {
    let names: string[];
    try {
      names = readdirSync(sp);
    } catch {
      continue;
    }
    for (const n of names) {
      const m = n.match(/^(.+?)-([^-]+?)(?:-py\d[\d.]*)?\.(?:dist-info|egg-info)$/);
      if (!m) continue;
      out.push({ ecosystem: 'PyPI', name: m[1].toLowerCase().replace(/[-_.]+/g, '-'), version: m[2], source: join(sp, n) });
    }
  }
  return out;
}

function isVenv(dir: string): boolean {
  return existsSync(join(dir, 'pyvenv.cfg'));
}

// Conda / Anaconda environments shared by several apps ("*" allowed in the last segment).
export const DEFAULT_PYTHON_ENVS = ['~/anaconda3', '~/anaconda3/envs/*', '~/miniconda3', '~/miniconda3/envs/*', '~/miniforge3', '~/miniforge3/envs/*'];

export function expandEnvs(patterns: string[]): string[] {
  const out: string[] = [];
  for (const raw of patterns) {
    const p = raw.replace(/^~(?=\/|$)/, homedir());
    if (p.endsWith('/*')) {
      const base = p.slice(0, -2);
      try {
        for (const d of readdirSync(base)) if (!d.startsWith('.')) out.push(join(base, d));
      } catch {
        /* missing */
      }
    } else if (existsSync(p)) out.push(p);
  }
  return out;
}

export function findLockfiles(roots: string[], skipDirs: string[], errors: CollectError[], venvs: string[] = []): string[] {
  const skip = new Set(skipDirs);
  const found: string[] = [];
  const deadline = Date.now() + MAX_SCAN_MS;
  let dirs = 0;
  let stopped = false;
  const walk = (dir: string, depth: number) => {
    if (stopped || found.length >= MAX_FILES || depth > 12) return;
    // a budget keeps huge or network-backed trees (iCloud Drive, NFS) from stalling the run
    if (++dirs > MAX_DIRS || Date.now() > deadline) {
      stopped = true;
      errors.push({ step: 'deps', message: `lockfile scan stopped early after ${dirs} directories / ${Math.round((Date.now() - deadline + MAX_SCAN_MS) / 1000)}s (narrow --scan or add --skip)` });
      return;
    }
    let entries;
    try {
      entries = readdirSync(dir, { withFileTypes: true });
    } catch (e) {
      if (depth === 0) errors.push({ step: 'deps', message: `cannot read ${dir}: ${errMsg(e)}` });
      return;
    }
    for (const e of entries) {
      if (e.isSymbolicLink()) continue;
      if (e.isDirectory()) {
        const full = join(dir, e.name);
        // project virtualenvs are read for installed packages instead of being walked
        if (isVenv(full)) venvs.push(full);
        else if (!skip.has(e.name)) walk(full, depth + 1);
      } else if (e.isFile() && (LOCKFILES.has(e.name) || isRequirements(e.name))) {
        found.push(join(dir, e.name));
      }
    }
  };
  for (const r of roots) {
    debug(`scan ${r}`);
    try {
      if (statSync(r).isDirectory()) walk(r, 0);
    } catch (e) {
      errors.push({ step: 'deps', message: `scan path ${r}: ${errMsg(e)}` });
    }
  }
  return found;
}

function parsePackageLock(text: string, source: string): Pkg[] {
  const j = JSON.parse(text);
  const out: Pkg[] = [];
  if (j.packages) {
    // lockfileVersion 2/3: keys are "node_modules/a/node_modules/b"
    for (const [key, v] of Object.entries<{ version?: string; link?: boolean }>(j.packages)) {
      if (!key || v.link || !v.version) continue;
      const name = key.slice(key.lastIndexOf('node_modules/') + 'node_modules/'.length);
      out.push({ ecosystem: 'npm', name, version: v.version, source });
    }
  } else if (j.dependencies) {
    // lockfileVersion 1: nested "dependencies"
    const walk = (deps: Record<string, { version?: string; dependencies?: object }>) => {
      for (const [name, v] of Object.entries(deps)) {
        if (v.version && !v.version.includes(':')) out.push({ ecosystem: 'npm', name, version: v.version, source });
        if (v.dependencies) walk(v.dependencies as never);
      }
    };
    walk(j.dependencies);
  }
  return out;
}

function parseComposerLock(text: string, source: string): Pkg[] {
  const j = JSON.parse(text);
  return [...(j.packages ?? []), ...(j['packages-dev'] ?? [])]
    .filter((p: { name?: string; version?: string }) => p.name && p.version)
    .map((p: { name: string; version: string }) => ({ ecosystem: 'Packagist', name: p.name, version: p.version.replace(/^v/, ''), source }));
}

// Only exact pins (==) can be matched reliably; ranges are skipped on purpose.
function parseRequirements(text: string, source: string): Pkg[] {
  const out: Pkg[] = [];
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.replace(/#.*/, '').trim();
    const m = line.match(/^([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]*\])?\s*===?\s*([A-Za-z0-9.!+_-]+)/);
    if (m) out.push({ ecosystem: 'PyPI', name: m[1].toLowerCase(), version: m[2], source });
  }
  return out;
}

export function collectDeps(roots: string[], skipDirs: string[], errors: CollectError[], pythonEnvs: string[] = DEFAULT_PYTHON_ENVS): Pkg[] {
  const pkgs: Pkg[] = [];
  const venvs: string[] = [];
  const files = findLockfiles(roots, skipDirs, errors, venvs);
  for (const env of [...new Set([...venvs, ...expandEnvs(pythonEnvs)])]) {
    debug(`site-packages ${env}`);
    pkgs.push(...sitePackages(env));
  }
  for (const file of files) {
    const text = readText(file);
    if (text == null) continue;
    try {
      if (file.endsWith('package-lock.json')) pkgs.push(...parsePackageLock(text, file));
      else if (file.endsWith('composer.lock')) pkgs.push(...parseComposerLock(text, file));
      else pkgs.push(...parseRequirements(text, file));
    } catch (e) {
      errors.push({ step: 'deps', message: `${file}: ${errMsg(e)}` });
    }
  }
  return pkgs;
}
