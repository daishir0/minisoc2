// Server-side aggregation for the log explorer. Given a measure (what to count), a dimension (how to split)
// and filters, it reads the pre-aggregated daily tables (log_daily / web_daily / web_ip_daily /
// log_rule_daily) and returns a sparse (dimValue × day → value) matrix the client pivots into any chart.
// Everything is whitelisted; filter values are parameterised.
import { q } from './db';
import { RAW_DIMS, type MeasureKey, type DimKey } from './logexplore';

interface MDef { table: string; val: string; fixed?: string }
const M: Record<MeasureKey, MDef> = {
  logs: { table: 'log_daily', val: 'sum(t.lines)' },
  web: { table: 'web_daily', val: 'sum(t.req)' },
  s4: { table: 'web_daily', val: 'sum(t.c4xx)' },
  s5: { table: 'web_daily', val: 'sum(t.c5xx)' },
  bytes: { table: 'web_daily', val: 'sum(t.bytes)' },
  rule: { table: 'log_rule_daily', val: 'sum(t.hits)' },
  failed: { table: 'log_rule_daily', val: 'sum(t.hits)', fixed: "t.rule_id='ssh_bruteforce'" },
  ips: { table: 'web_ip_daily', val: 'count(distinct t.ip)' },
  ipreq: { table: 'web_ip_daily', val: 'sum(t.req)' },
};

const CAT_CASE = `CASE WHEN t.source ~* 'access[_.]log' THEN 'web' WHEN t.source ~* 'auth\\.log|secure|sshd|sudo|fail2ban' THEN 'auth' WHEN t.source ~* 'audit' THEN 'audit' ELSE 'sys' END`;
const CAT_RE: Record<string, string> = {
  web: "t.source ~* 'access[_.]log'",
  auth: "t.source ~* 'auth\\.log|secure|sshd|sudo|fail2ban'",
  audit: "t.source ~* 'audit'",
  sys: "NOT (t.source ~* 'access[_.]log|auth\\.log|secure|sshd|sudo|fail2ban|audit')",
};

function dimExpr(table: string, dim: DimKey): string | null {
  if (dim === 'host') return 't.host_id::text'; // id; the client maps it to the (maskable) host name
  if (dim === 'day') return "to_char(t.day,'YYYY-MM-DD')";
  if (table === 'log_daily') { if (dim === 'cat') return CAT_CASE; if (dim === 'source') return 't.source'; }
  if (table === 'web_daily' && dim === 'vhost') return 't.vhost';
  if (table === 'web_ip_daily' && dim === 'vhost') return 't.vhost';
  if (table === 'web_ip_daily' && dim === 'ip') return 't.ip';
  if (table === 'log_rule_daily' && dim === 'rule') return 't.rule_id';
  return null;
}

export interface AggParams { measure: MeasureKey; dim: DimKey; days: number; filters: Record<string, string | undefined> }
export interface AggResult { days: string[]; rows: { k: string; d: string; v: number }[] }

// Raw dimensions (path / ua / msg) are extracted on demand from raw_logs.message, since the daily
// rollups do not carry them. Bounded by the raw-log retention window (so the series is shorter than the
// rollup-backed measures). Only total mode; anomaly ranking falls back to empty for these dims.
const rawDimExpr: Record<'path' | 'ua' | 'msg', string> = {
  // request-line path without method or query string: `"GET /a/b?x=1 HTTP/1.1"` -> `/a/b`
  path: `substring(t.message from '"[A-Z]+ ([^ ?"]+)')`,
  // combined-log User-Agent is the last quoted field
  ua: `substring(t.message from '"([^"]*)"[[:space:]]*$')`,
  // normalise a journal/syslog line to a repeatable shape: drop a leading "Mon DD HH:MM:SS host proc[pid]:"
  // prefix, then collapse uuids and numbers, and cap length
  msg: `left(regexp_replace(regexp_replace(regexp_replace(t.message,
      '^[[:alpha:]]{3}[[:space:]]+[0-9]+[[:space:]]+[0-9:]+[[:space:]]+[^[:space:]]+[[:space:]]+[^[:space:]]+?:[[:space:]]*', ''),
      '[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', '<uuid>', 'gi'),
      '[0-9]+', 'N', 'g'), 160)`,
};

async function aggregateRaw(p: AggParams, days: string[]): Promise<AggResult> {
  const dim = p.dim as 'path' | 'ua' | 'msg';
  const dexpr = rawDimExpr[dim];
  const f = p.filters;
  const params: unknown[] = [];
  const where: string[] = [`t.received_at > now() - interval '${p.days + 1} days'`];
  if (f.host && /^[0-9a-f-]{36}$/.test(f.host)) { params.push(f.host); where.push(`t.host_id=$${params.length}`); }
  if (f.day && /^\d{4}-\d{2}-\d{2}$/.test(f.day)) { params.push(f.day); where.push(`coalesce(t.ts, t.received_at)::date=$${params.length}::date`); }
  if (f.source) { params.push(f.source); where.push(`t.source=$${params.length}`); }
  else if (dim === 'msg') where.push(`t.source !~* 'access[_.]log'`);
  else where.push(`t.source ~* 'access[_.]log'`); // path / ua are web-only
  if (f.ip && /^[0-9a-f:.]{3,45}$/i.test(f.ip)) { params.push('%' + f.ip + '%'); where.push(`t.message LIKE $${params.length}`); }
  if (f.path && /^[\w/.~:%@+-]{1,300}$/.test(f.path)) { params.push(f.path); where.push(`${rawDimExpr.path}=$${params.length}`); }
  // status: exact "200" or a class "4xx"; the response status is the number after the quoted request
  const statusExpr = `substring(t.message from '" ([0-9]{3}) ')`;
  if (f.status && /^[0-9]{3}$/.test(f.status)) { params.push(f.status); where.push(`${statusExpr}=$${params.length}`); }
  else if (f.status && /^[1-5]xx$/.test(f.status)) where.push(`${statusExpr} LIKE '${f.status[0]}%'`);
  // measures s4/s5 restrict to their status class even without an explicit status filter
  if (p.measure === 's4') where.push(`${statusExpr} LIKE '4%'`);
  else if (p.measure === 's5') where.push(`${statusExpr} LIKE '5%'`);

  const rows = await q<{ k: string | null; d: string; v: string }>(
    `SELECT ${dexpr} AS k, to_char(coalesce(t.ts, t.received_at),'YYYY-MM-DD') AS d, count(*)::text AS v
     FROM raw_logs t WHERE ${where.join(' AND ')} AND ${dexpr} IS NOT NULL AND ${dexpr} <> ''
     GROUP BY k, d`, params);
  return { days, rows: rows.map((r) => ({ k: r.k ?? '(なし)', d: r.d, v: Number(r.v) })) };
}

export async function aggregate(p: AggParams): Promise<AggResult> {
  const m = M[p.measure];
  const days = Array.from({ length: p.days }, (_, i) => new Date(Date.now() - (p.days - 1 - i) * 86400_000).toISOString().slice(0, 10));
  if (RAW_DIMS.includes(p.dim)) return aggregateRaw(p, days);
  if (!m) return { days, rows: [] };
  const params: unknown[] = [];
  const where: string[] = [`t.day > current_date - ${p.days}`];
  const f = p.filters;
  if (f.host && /^[0-9a-f-]{36}$/.test(f.host)) { params.push(f.host); where.push(`t.host_id=$${params.length}`); }
  if (f.day && /^\d{4}-\d{2}-\d{2}$/.test(f.day)) { params.push(f.day); where.push(`t.day=$${params.length}::date`); }
  if (m.fixed) where.push(m.fixed);
  if (m.table === 'log_daily') {
    if (f.cat && CAT_RE[f.cat]) where.push(`(${CAT_RE[f.cat]})`);
    if (f.source) { params.push(f.source); where.push(`t.source=$${params.length}`); }
  }
  if ((m.table === 'web_daily' || m.table === 'web_ip_daily') && f.vhost && /^[\w.*-]{1,120}$/.test(f.vhost)) { params.push(f.vhost); where.push(`t.vhost=$${params.length}`); }
  if (m.table === 'web_ip_daily' && f.ip && /^[0-9a-f:.]{3,45}$/i.test(f.ip)) { params.push(f.ip); where.push(`t.ip=$${params.length}`); }
  if (m.table === 'log_rule_daily' && f.rule && /^[\w:.-]{1,80}$/.test(f.rule)) { params.push(f.rule); where.push(`t.rule_id=$${params.length}`); }

  // status is special to web: the breakdown is the four status classes (unpivoted from the columns).
  if (p.dim === 'status' && m.table === 'web_daily') {
    const rr = await q<{ d: string; s2: string; s3: string; s4: string; s5: string }>(
      `SELECT to_char(t.day,'YYYY-MM-DD') AS d, sum(t.req - t.c3xx - t.c4xx - t.c5xx) AS s2, sum(t.c3xx) AS s3, sum(t.c4xx) AS s4, sum(t.c5xx) AS s5
       FROM web_daily t WHERE ${where.join(' AND ')} GROUP BY d`, params);
    const rows: AggResult['rows'] = [];
    for (const r of rr) {
      ([['2xx', r.s2], ['3xx', r.s3], ['4xx', r.s4], ['5xx', r.s5]] as [string, string][]).forEach(([k, v]) => {
        const n = Math.max(0, Number(v)); if (n > 0) rows.push({ k, d: r.d, v: n });
      });
    }
    return { days, rows };
  }

  const dexpr = dimExpr(m.table, p.dim);
  if (!dexpr) return { days, rows: [] };
  const rows = await q<{ k: string | null; d: string; v: string }>(
    `SELECT ${dexpr} AS k, to_char(t.day,'YYYY-MM-DD') AS d, ${m.val} AS v
     FROM ${m.table} t WHERE ${where.join(' AND ')} GROUP BY k, d HAVING ${m.val} > 0`, params);
  return { days, rows: rows.map((r) => ({ k: r.k ?? '(なし)', d: r.d, v: Number(r.v) })) };
}

// Build the shared WHERE for a measure+filters (excluding the day window, which each caller supplies).
function whereFor(m: MDef, dim: DimKey, f: Record<string, string | undefined>): { where: string[]; params: unknown[] } | null {
  if (!dimExpr(m.table, dim)) return null;
  const params: unknown[] = []; const where: string[] = [];
  if (f.host && /^[0-9a-f-]{36}$/.test(f.host)) { params.push(f.host); where.push(`t.host_id=$${params.length}`); }
  if (m.fixed) where.push(m.fixed);
  if (m.table === 'log_daily') {
    if (f.cat && CAT_RE[f.cat]) where.push(`(${CAT_RE[f.cat]})`);
    if (f.source) { params.push(f.source); where.push(`t.source=$${params.length}`); }
  }
  if ((m.table === 'web_daily' || m.table === 'web_ip_daily') && f.vhost && /^[\w.*-]{1,120}$/.test(f.vhost)) { params.push(f.vhost); where.push(`t.vhost=$${params.length}`); }
  if (m.table === 'web_ip_daily' && f.ip && /^[0-9a-f:.]{3,45}$/i.test(f.ip)) { params.push(f.ip); where.push(`t.ip=$${params.length}`); }
  if (m.table === 'log_rule_daily' && f.rule && /^[\w:.-]{1,80}$/.test(f.rule)) { params.push(f.rule); where.push(`t.rule_id=$${params.length}`); }
  return { where, params };
}

export interface DevRow { k: string; cur: number; base: number; ratio: number }

// Anomaly view: how far today / this week is from normal. ratio = 直近1日 ÷ 直近7日平均（当日は未完なので昨日を
// 当日扱い）; wow = 今週(直近7日) ÷ 前週(その前の7日). The baseline is floored to 1 so a brand-new signal
// (normally 0) still ranks as a large ratio. Returns the top movers, ratio-descending.
export async function aggregateDeviation(p: AggParams, mode: 'ratio' | 'wow'): Promise<{ mode: string; rows: DevRow[] }> {
  const m = M[p.measure];
  if (!m) return { mode, rows: [] };
  const dexpr = dimExpr(m.table, p.dim);
  const built = dexpr ? whereFor(m, p.dim, p.filters) : null;
  if (!dexpr || !built) return { mode, rows: [] };
  const curCond = mode === 'ratio' ? 't.day = current_date-1' : 't.day > current_date-7';
  const baseCond = mode === 'ratio' ? 't.day BETWEEN current_date-8 AND current_date-2' : 't.day BETWEEN current_date-14 AND current_date-8';
  const windowCond = mode === 'ratio' ? 't.day BETWEEN current_date-8 AND current_date-1' : 't.day > current_date-14';
  const where = [...built.where, windowCond].join(' AND ');
  const rows = await q<{ k: string | null; cur: string | null; base: string | null }>(
    `SELECT ${dexpr} AS k,
       ${m.val} FILTER (WHERE ${curCond}) AS cur,
       ${m.val} FILTER (WHERE ${baseCond}) AS base
     FROM ${m.table} t WHERE ${where} GROUP BY k`, built.params);
  const out: DevRow[] = [];
  for (const r of rows) {
    const cur = Number(r.cur ?? 0);
    const baseRaw = Number(r.base ?? 0);
    const base = mode === 'ratio' ? baseRaw / 7 : baseRaw; // ratio: 7-day average; wow: prior-week total
    if (cur <= 0 && base <= 0) continue;
    out.push({ k: r.k ?? '(なし)', cur, base, ratio: cur / Math.max(base, 1) });
  }
  out.sort((a, b) => b.ratio - a.ratio);
  return { mode, rows: out.slice(0, 25) };
}
