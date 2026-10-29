// AIDE-style file-integrity scan. Walks the configured paths read-only, hashes each regular file
// (sha256) and reports path/hash/size/mtime. The server keeps the baseline and detects changes, so
// the host stores nothing authoritative and is never written to. A local cache avoids re-hashing
// files whose size and mtime are unchanged since the previous run, keeping hourly runs cheap.
import { createHash } from 'node:crypto';
import { closeSync, openSync, readdirSync, readFileSync, readSync, statSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { DEFAULT_AIDE_PATHS, minisoc2Home, type AgentConfig } from '../config.js';
import type { CollectError, FileHash } from '../types.js';

const MAX_FILES = 60_000;
const MAX_TOTAL_BYTES = 2 * 1024 * 1024 * 1024; // stop hashing after ~2 GB of reads in one run
const MAX_FILE_BYTES = 200 * 1024 * 1024; // files larger than this are tracked by size+mtime only
const MAX_MS = 180_000;

type CacheEntry = { s: number; m: number; h: string };

function loadCache(): Record<string, CacheEntry> {
  try {
    return JSON.parse(readFileSync(join(minisoc2Home(), 'integritystate.json'), 'utf8')) as Record<string, CacheEntry>;
  } catch {
    return {};
  }
}

function sha256File(path: string, size: number): string {
  if (size <= MAX_FILE_BYTES) return createHash('sha256').update(readFileSync(path)).digest('hex');
  // stream very large files in chunks so memory stays bounded
  const h = createHash('sha256');
  const fd = openSync(path, 'r');
  try {
    const buf = Buffer.alloc(1024 * 1024);
    let n: number;
    while ((n = readSync(fd, buf, 0, buf.length, null)) > 0) h.update(buf.subarray(0, n));
  } finally {
    closeSync(fd);
  }
  return h.digest('hex');
}

// Expand a single "*" in the last-but-one segment (e.g. /home/*/.ssh -> /home/alice/.ssh).
function expandGlob(pattern: string): string[] {
  const i = pattern.indexOf('*');
  if (i < 0) return [pattern];
  const head = pattern.slice(0, i).replace(/\/[^/]*$/, '');
  const afterStar = pattern.slice(i + 1).replace(/^[^/]*/, ''); // rest from the first "/" after "*"
  try {
    return readdirSync(head, { withFileTypes: true })
      .filter((d) => d.isDirectory())
      .map((d) => join(head, d.name) + afterStar);
  } catch {
    return [];
  }
}

export function fileIntegrity(cfg: AgentConfig, errors: CollectError[]): { files: FileHash[]; truncated: boolean } {
  const started = Date.now();
  const skip = new Set(cfg.skipDirs);
  const cache = loadCache();
  const next: Record<string, CacheEntry> = {};
  const out: FileHash[] = [];
  let bytes = 0;
  let truncated = false;
  const seenDir = new Set<string>(); // guard against symlink loops

  const walk = (dir: string) => {
    if (truncated) return;
    let entries: import('node:fs').Dirent[];
    try {
      entries = readdirSync(dir, { withFileTypes: true });
    } catch {
      return; // unreadable directory: skipped silently (many default paths need root)
    }
    for (const e of entries) {
      if (out.length >= MAX_FILES || bytes >= MAX_TOTAL_BYTES || Date.now() - started > MAX_MS) {
        truncated = true;
        return;
      }
      const full = join(dir, e.name);
      if (e.isSymbolicLink()) continue; // AIDE records link targets; we skip to avoid escaping the tree
      if (e.isDirectory()) {
        if (skip.has(e.name)) continue;
        let real: string;
        try {
          real = statSync(full).isDirectory() ? full : '';
        } catch {
          continue;
        }
        if (real && !seenDir.has(full)) {
          seenDir.add(full);
          walk(full);
        }
        continue;
      }
      if (!e.isFile()) continue;
      let st: ReturnType<typeof statSync>;
      try {
        st = statSync(full);
      } catch {
        continue;
      }
      const size = st.size;
      const mtime = Math.round(st.mtimeMs);
      const cached = cache[full];
      let hash: string;
      if (cached && cached.s === size && cached.m === mtime) {
        hash = cached.h;
      } else {
        try {
          hash = sha256File(full, size);
          bytes += size;
        } catch {
          continue; // unreadable file (e.g. not root): skipped
        }
      }
      next[full] = { s: size, m: mtime, h: hash };
      out.push({ p: full, h: hash, s: size, m: mtime });
    }
  };

  const roots = [...new Set((cfg.aidePaths ?? DEFAULT_AIDE_PATHS).flatMap(expandGlob))];
  for (const r of roots) {
    try {
      const st = statSync(r);
      if (st.isDirectory()) walk(r);
      else if (st.isFile()) {
        const hash = sha256File(r, st.size);
        next[r] = { s: st.size, m: Math.round(st.mtimeMs), h: hash };
        out.push({ p: r, h: hash, s: st.size, m: Math.round(st.mtimeMs) });
      }
    } catch {
      /* missing root: skip */
    }
  }
  if (truncated) errors.push({ step: 'files', message: `integrity scan hit its budget (${out.length} files); baseline is partial this run` });
  try {
    writeFileSync(join(minisoc2Home(), 'integritystate.json'), JSON.stringify(next), { mode: 0o600 });
  } catch {
    /* cache is best effort */
  }
  return { files: out, truncated };
}
