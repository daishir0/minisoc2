// Log ingestion: store raw lines in daily partitions, keep permanent daily aggregates,
// run the detection rules and raise alerts.
import { raiseAlert } from './alerts';
import { q, q1, tx } from './db';
import type { HostRow } from './ingest';
import type { LogBatch } from './payload';
import { recordEvent } from './events';
import { matchLine, type Hit } from './rules';
import { getPolicy, getSetting } from './settings';

const partitions = new Set<string>();

function utcDay(d: Date): string {
  return d.toISOString().slice(0, 10);
}

export async function ensurePartition(day: string): Promise<void> {
  if (partitions.has(day)) return;
  const name = `raw_logs_${day.replace(/-/g, '')}`;
  const next = utcDay(new Date(Date.parse(`${day}T00:00:00Z`) + 86400_000));
  try {
    await q(`CREATE TABLE IF NOT EXISTS ${name} PARTITION OF raw_logs FOR VALUES FROM ('${day} 00:00:00+00') TO ('${next} 00:00:00+00')`);
  } catch (e) {
    // a concurrent request may have created it between IF NOT EXISTS and CREATE
    if (!/already exists/.test(String(e))) throw e;
  }
  partitions.add(day);
}

export async function rawIngestPaused(): Promise<boolean> {
  return (await getSetting<{ paused: boolean }>('raw_ingest', { paused: false })).paused;
}

export async function ingestLogs(host: HostRow, batch: LogBatch): Promise<{ lines: number; storedRaw: boolean; hits: number }> {
  const now = new Date();
  const entries = batch.entries.filter((e) => e && typeof e.m === 'string' && typeof e.s === 'string');
  const paused = await rawIngestPaused();
  // The first 30 minutes of a host's logs only build the "seen" baseline (an upload is split into
  // several batches, and the initial backlog contains every normal login).
  const first = await q1<{ t: Date | null }>('SELECT min(received_at) AS t FROM log_batches WHERE host_id=$1', [host.id]);
  const firstBatch = !first?.t || Date.now() - new Date(first.t).getTime() < 30 * 60_000;

  // 1. raw lines (skipped while the disk guard is active; aggregates and rules still run)
  if (!paused && entries.length) {
    await ensurePartition(utcDay(now));
    for (let i = 0; i < entries.length; i += 5000) {
      const ch = entries.slice(i, i + 5000);
      await q(
        `INSERT INTO raw_logs(host_id, received_at, ts, source, message)
         SELECT $1, $2, t, s, m FROM unnest($3::timestamptz[], $4::text[], $5::text[]) AS x(t, s, m)`,
        [host.id, now, ch.map((e) => (e.t && !Number.isNaN(Date.parse(e.t)) ? e.t : null)), ch.map((e) => e.s.slice(0, 300)), ch.map((e) => e.m.replace(/\u0000/g, ''))],
      );
    }
  }

  // 2. permanent daily aggregates per source
  const agg = new Map<string, { day: string; source: string; lines: number; bytes: number }>();
  for (const e of entries) {
    const day = utcDay(e.t && !Number.isNaN(Date.parse(e.t)) ? new Date(e.t) : now);
    const k = `${day}\u0000${e.s}`;
    const a = agg.get(k) ?? { day, source: e.s.slice(0, 300), lines: 0, bytes: 0 };
    a.lines++;
    a.bytes += e.m.length;
    agg.set(k, a);
  }
  if (agg.size) {
    const rows = [...agg.values()];
    await q(
      `INSERT INTO log_daily(host_id, day, source, lines, bytes)
       SELECT $1, d, s, l, b FROM unnest($2::date[], $3::text[], $4::bigint[], $5::bigint[]) AS x(d, s, l, b)
       ON CONFLICT (host_id, day, source) DO UPDATE SET lines = log_daily.lines + EXCLUDED.lines, bytes = log_daily.bytes + EXCLUDED.bytes`,
      [host.id, rows.map((r) => r.day), rows.map((r) => r.source), rows.map((r) => r.lines), rows.map((r) => r.bytes)],
    );
  }

  // 3. detection rules
  const hits: Hit[] = [];
  for (const e of entries) {
    const ts = e.t && !Number.isNaN(Date.parse(e.t)) ? new Date(e.t) : now;
    hits.push(...matchLine(e.s, e.m, ts));
  }
  if (hits.length) await handleHits(host, hits, firstBatch);

  await q('INSERT INTO log_batches(host_id, lines, bytes, stored_raw, truncated) VALUES ($1,$2,$3,$4,$5)', [
    host.id, entries.length, entries.reduce((s, e) => s + e.m.length, 0), !paused, Math.max(0, Number(batch.truncated) || 0),
  ]);
  if (batch.truncated) {
    await raiseAlert({ kind: 'agent', severity: 'low', hostId: host.id, title: `[${host.name}] ログが1回の上限を超えたため一部を次回に繰り越しました`, dedupeKey: `logtrunc:${host.id}:${utcDay(now)}` });
  }
  return { lines: entries.length, storedRaw: !paused, hits: hits.length };
}

async function logEvent(host: HostRow, severity: string, title: string, sample: string): Promise<void> {
  await recordEvent({ hostId: host.id, kind: 'log', important: severity === 'critical', title: title.replace(/^\[[^\]]+\] /, `${host.name}：`), detail: sample.slice(0, 500) });
}

async function handleHits(host: HostRow, hits: Hit[], firstBatch: boolean): Promise<void> {
  await tx(async (c) => {
    for (let i = 0; i < hits.length; i += 2000) {
      const ch = hits.slice(i, i + 2000);
      await c.query(
        `INSERT INTO log_hits(host_id, rule_id, ts, grp, sample) SELECT $1, r, t, g, s FROM unnest($2::text[], $3::timestamptz[], $4::text[], $5::text[]) AS x(r, t, g, s)`,
        [host.id, ch.map((h) => h.rule.id), ch.map((h) => h.ts), ch.map((h) => h.grp), ch.map((h) => h.sample)],
      );
    }
    const daily = new Map<string, number>();
    for (const h of hits) {
      const k = `${utcDay(h.ts)}\u0000${h.rule.id}`;
      daily.set(k, (daily.get(k) ?? 0) + 1);
    }
    for (const [k, n] of daily) {
      const [day, rule] = k.split('\u0000');
      await c.query(
        `INSERT INTO log_rule_daily(host_id, day, rule_id, hits) VALUES ($1,$2,$3,$4)
         ON CONFLICT (host_id, day, rule_id) DO UPDATE SET hits = log_rule_daily.hits + EXCLUDED.hits`,
        [host.id, day, rule, n],
      );
    }
  });

  // group hits per rule + group value
  const ignoreIps = new Set((await getPolicy()).ignoreIps ?? []);
  const groups = new Map<string, Hit[]>();
  for (const h of hits) {
    if (h.rule.alert === false || ignoreIps.has(h.grp)) continue;
    const k = `${h.rule.id}\u0000${h.grp}`;
    groups.set(k, [...(groups.get(k) ?? []), h]);
  }
  for (const list of groups.values()) {
    const { rule, grp } = list[0];
    const last = list[list.length - 1];
    const label = `[${host.name}] ${rule.title}${grp ? `：${grp}` : ''}`;
    if (rule.firstSeen) {
      const r = await q1<{ inserted: boolean }>(
        `INSERT INTO log_seen(host_id, kind, value) VALUES ($1,$2,$3)
         ON CONFLICT (host_id, kind, value) DO UPDATE SET last_seen=now() RETURNING (xmax = 0) AS inserted`,
        [host.id, rule.firstSeen, grp],
      );
      if (r?.inserted && !firstBatch) {
        await logEvent(host, rule.severity, label, last.sample);
        await raiseAlert({ kind: 'log', severity: rule.severity, hostId: host.id, title: label, detail: last.sample, dedupeKey: `log:${rule.id}:${host.id}:${grp}` });
      }
    } else if (rule.threshold) {
      const { count, windowMin } = rule.threshold;
      const n = await q1<{ n: string }>(
        "SELECT count(*) AS n FROM log_hits WHERE host_id=$1 AND rule_id=$2 AND grp=$3 AND ts > $4::timestamptz - ($5 || ' minutes')::interval",
        [host.id, rule.id, grp, last.ts, String(windowMin)],
      );
      if (Number(n?.n ?? 0) >= count) {
        const bucket = Math.floor(last.ts.getTime() / (windowMin * 60_000));
        await logEvent(host, rule.severity, `${label}（${windowMin}分で${n?.n}件）`, last.sample);
        await raiseAlert({ kind: 'log', severity: rule.severity, hostId: host.id, title: `${label}（${windowMin}分で${n?.n}件）`, detail: last.sample, dedupeKey: `log:${rule.id}:${host.id}:${grp}:${bucket}` });
      }
    } else {
      const hour = Math.floor(last.ts.getTime() / 3600_000);
      await logEvent(host, rule.severity, list.length > 1 ? `${label}（${list.length}件）` : label, last.sample);
      await raiseAlert({ kind: 'log', severity: rule.severity, hostId: host.id, title: list.length > 1 ? `${label}（${list.length}件）` : label, detail: last.sample, dedupeKey: `log:${rule.id}:${host.id}:${grp}:${hour}` });
    }
  }
}

// Retention: drop whole daily partitions older than the configured number of days.
export async function dropOldPartitions(retentionDays: number): Promise<string[]> {
  const parts = await q<{ name: string }>(
    "SELECT c.relname AS name FROM pg_inherits i JOIN pg_class c ON c.oid=i.inhrelid JOIN pg_class p ON p.oid=i.inhparent WHERE p.relname='raw_logs'",
  );
  const cutoff = utcDay(new Date(Date.now() - retentionDays * 86400_000)).replace(/-/g, '');
  const dropped: string[] = [];
  for (const { name } of parts) {
    const m = name.match(/^raw_logs_(\d{8})$/);
    if (m && m[1] < cutoff) {
      await q(`DROP TABLE IF EXISTS ${name}`);
      partitions.delete(`${m[1].slice(0, 4)}-${m[1].slice(4, 6)}-${m[1].slice(6)}`);
      dropped.push(name);
    }
  }
  return dropped;
}
