// Sigma (SigmaHQ) log detection, pragmatically adapted to raw syslog lines. Sigma normally runs on
// structured fields; our hosts send raw lines, so at sync time we keep only rules whose detection
// reduces to keyword/substring groups and compile them to an AND-of-ORs line matcher. Rules needing
// real field logic are skipped (counted, not guessed), so what fires is honest.
import { gunzipSync } from 'node:zlib';
import { parse as parseYaml } from 'yaml';
import { markFeed } from './feeds';
import { q } from './db';
import type { LogRule, Hit } from './rules';

const TARBALL = 'https://codeload.github.com/SigmaHQ/sigma/tar.gz/refs/heads/master';
const MAX_RULES = 1500;
const MAX_GROUPS = 12;
const MAX_NEEDLES_PER_GROUP = 40;

// ---- minimal tar reader (gzip already removed) ----
interface TarEntry { name: string; data: Buffer }
function* readTar(buf: Buffer): Generator<TarEntry> {
  let off = 0;
  let longName = '';
  while (off + 512 <= buf.length) {
    const header = buf.subarray(off, off + 512);
    if (header.every((b) => b === 0)) break; // end of archive
    const readStr = (start: number, len: number) => header.subarray(start, start + len).toString('utf8').replace(/\0.*$/, '').trim();
    const sizeOct = readStr(124, 12);
    const size = parseInt(sizeOct, 8) || 0;
    const type = String.fromCharCode(header[156]);
    const prefix = readStr(345, 155);
    let name = readStr(0, 100);
    if (prefix) name = `${prefix}/${name}`;
    const dataStart = off + 512;
    const data = buf.subarray(dataStart, dataStart + size);
    off = dataStart + Math.ceil(size / 512) * 512;
    if (type === 'L') { // GNU long name: applies to the next entry
      longName = data.toString('utf8').replace(/\0.*$/, '');
      continue;
    }
    if (longName) { name = longName; longName = ''; }
    if (type === '0' || type === '\0') yield { name, data };
  }
}

type Sev = LogRule['severity'];
function levelToSev(level: string): Sev {
  const l = (level ?? '').toLowerCase();
  if (l === 'critical') return 'critical';
  if (l === 'high') return 'high';
  if (l === 'medium') return 'medium';
  return 'low'; // low / informational / unknown
}

interface SigmaDoc {
  id?: string;
  title?: string;
  level?: string;
  references?: string[];
  logsource?: { product?: string; service?: string; category?: string };
  detection?: Record<string, unknown> & { condition?: unknown };
}

export interface CompiledSigma { id: string; title: string; level: Sev; sourceRe: string; needles: string[][]; reference: string }

// Services we can reliably pin to a log source; otherwise the rule applies to any source.
const SERVICE_RE: Record<string, string> = { sshd: 'sshd', ssh: 'sshd', sudo: 'sudo', cron: 'cron', auth: '', auditd: '' };

function stringsOf(v: unknown): string[] {
  if (typeof v === 'string') return v ? [v] : [];
  if (typeof v === 'number' || typeof v === 'boolean') return [String(v)];
  if (Array.isArray(v)) return v.flatMap(stringsOf);
  return [];
}

// Build AND-of-ORs groups from one selection block.
function groupsFromSelection(sel: unknown): string[][] | null {
  if (sel == null) return null;
  if (Array.isArray(sel) || typeof sel === 'string') {
    const g = stringsOf(sel);
    return g.length ? [g] : null;
  }
  if (typeof sel === 'object') {
    const out: string[][] = [];
    for (const [key, val] of Object.entries(sel as Record<string, unknown>)) {
      const mods = key.split('|').slice(1);
      if (mods.includes('re') || mods.includes('base64') || mods.includes('base64offset') || mods.includes('cidr')) return null; // not substring-friendly
      const vals = stringsOf(val);
      if (!vals.length) continue; // numeric/other field: ignore (keeps the remaining groups)
      if (mods.includes('all')) for (const v of vals) out.push([v]); // all values required
      else out.push(vals); // any of the values
    }
    return out.length ? out : null;
  }
  return null;
}

// Only accept conditions that are an AND of positive selection names (no or/not/of/parentheses).
function requiredSelections(condition: unknown): string[] | null {
  if (typeof condition !== 'string') return null;
  const c = condition.trim().toLowerCase();
  if (/\b(or|not|1 of|all of|any of)\b|[()|]/.test(c)) return null;
  const names = c.split(/\s+and\s+/).map((s) => s.trim()).filter(Boolean);
  return names.length ? names : null;
}

export function compileRule(doc: SigmaDoc): CompiledSigma | null {
  if (!doc || doc.logsource?.product !== 'linux') return null;
  if (!doc.id || !doc.detection) return null;
  const names = requiredSelections(doc.detection.condition);
  if (!names) return null;
  const groups: string[][] = [];
  for (const name of names) {
    const sel = (doc.detection as Record<string, unknown>)[name];
    if (sel === undefined) return null; // condition references something we did not model
    const g = groupsFromSelection(sel);
    if (!g) return null;
    groups.push(...g);
  }
  if (!groups.length) return null;
  // Drop very short substrings (they match too much). If that empties a group, the rule would match
  // on weak evidence, so skip it entirely rather than fire noisily.
  const needles: string[][] = [];
  for (const g of groups.slice(0, MAX_GROUPS)) {
    const kept = [...new Set(g.map((s) => s.toLowerCase()).filter((s) => s.length >= 4))].slice(0, MAX_NEEDLES_PER_GROUP);
    if (!kept.length) return null;
    needles.push(kept);
  }
  const service = (doc.logsource?.service ?? '').toLowerCase();
  return {
    id: `sigma:${doc.id}`,
    title: (doc.title ?? 'Sigma rule').slice(0, 300),
    level: levelToSev(doc.level ?? ''),
    sourceRe: service in SERVICE_RE ? SERVICE_RE[service] : '',
    needles,
    reference: (doc.references?.[0] ?? '').slice(0, 500),
  };
}

export async function syncSigma(): Promise<{ kept: number; total: number }> {
  try {
    const res = await fetch(TARBALL, { headers: { 'user-agent': 'minisoc2' }, redirect: 'follow' });
    if (!res.ok) throw new Error(`sigma download HTTP ${res.status}`);
    const tar = gunzipSync(Buffer.from(await res.arrayBuffer()));
    let total = 0;
    const compiled: CompiledSigma[] = [];
    for (const entry of readTar(tar)) {
      if (!/\/rules\/linux\/.*\.ya?ml$/.test(entry.name)) continue;
      total++;
      let doc: SigmaDoc;
      try {
        doc = parseYaml(entry.data.toString('utf8')) as SigmaDoc;
      } catch {
        continue;
      }
      const c = compileRule(doc);
      if (c) compiled.push(c);
      if (compiled.length >= MAX_RULES) break;
    }
    if (!total) throw new Error('no linux rules found in the archive (format change?)');
    if (!compiled.length) throw new Error('no compilable rules (all needed structured fields?)');
    // replace the set atomically-ish: upsert all, then delete rules no longer present
    const ids = compiled.map((c) => c.id);
    for (let i = 0; i < compiled.length; i += 500) {
      const ch = compiled.slice(i, i + 500);
      await q(
        `INSERT INTO sigma_rules(id, title, level, source_re, needles, reference, updated_at)
         SELECT * , now() FROM unnest($1::text[], $2::text[], $3::text[], $4::text[], $5::jsonb[], $6::text[]) AS t(id, title, level, source_re, needles, reference)
         ON CONFLICT (id) DO UPDATE SET title=EXCLUDED.title, level=EXCLUDED.level, source_re=EXCLUDED.source_re,
           needles=EXCLUDED.needles, reference=EXCLUDED.reference, updated_at=now()`,
        [ch.map((c) => c.id), ch.map((c) => c.title), ch.map((c) => c.level), ch.map((c) => c.sourceRe), ch.map((c) => JSON.stringify(c.needles)), ch.map((c) => c.reference)],
      );
    }
    await q('DELETE FROM sigma_rules WHERE NOT (id = ANY($1::text[]))', [ids]);
    await markFeed('sigma', true, { count: compiled.length });
    return { kept: compiled.length, total };
  } catch (e) {
    await markFeed('sigma', false, { error: e instanceof Error ? e.message : String(e) });
    throw e;
  }
}

// ---- runtime matching ----
interface LoadedSigma { rule: LogRule; sourceRe: RegExp | null; needles: string[][] }
let cache: { at: number; rules: LoadedSigma[] } | null = null;
const TTL_MS = 10 * 60_000;

export async function getSigmaRules(): Promise<LoadedSigma[]> {
  if (cache && Date.now() - cache.at < TTL_MS) return cache.rules;
  const rows = await q<{ id: string; title: string; level: Sev; source_re: string; needles: string[][] }>(
    'SELECT id, title, level, source_re, needles FROM sigma_rules WHERE enabled',
  );
  const rules = rows.map((r) => ({
    rule: { id: r.id, title: r.title, severity: r.level, pattern: /(?:)/, alert: true } as LogRule,
    sourceRe: r.source_re ? new RegExp(r.source_re) : null,
    needles: r.needles,
  }));
  cache = { at: Date.now(), rules };
  return rules;
}

export function matchSigma(rules: LoadedSigma[], source: string, message: string, ts: Date): Hit[] {
  const lower = message.toLowerCase();
  const out: Hit[] = [];
  for (const r of rules) {
    if (r.sourceRe && !r.sourceRe.test(source)) continue;
    if (r.needles.every((group) => group.some((n) => lower.includes(n)))) {
      out.push({ rule: r.rule, grp: '', ts, sample: message.slice(0, 1000) });
    }
  }
  return out;
}
