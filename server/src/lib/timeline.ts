// Day-grouped change timeline (shared by the dashboard and the history page).
import { q } from './db';

export interface DayGroup {
  day: string; // YYYY-MM-DD (server time)
  items: { title: string; kind: string; important: boolean; count: number; host_id: string | null; system_root: string | null }[];
}

export async function timeline(opts: { days: number; importantOnly: boolean; hostId?: string; kind?: string }): Promise<DayGroup[]> {
  const where = [`ts > now() - ($1 || ' days')::interval`];
  const params: unknown[] = [String(opts.days)];
  if (opts.importantOnly) where.push('important');
  if (opts.hostId) { params.push(opts.hostId); where.push(`host_id=$${params.length}`); }
  if (opts.kind) { params.push(opts.kind); where.push(`kind=$${params.length}`); }
  const rows = await q<{ day: string; title: string; kind: string; important: boolean; count: number; host_id: string | null; system_root: string | null }>(
    `SELECT to_char(ts, 'YYYY-MM-DD') AS day, title, kind, important, count, host_id, system_root
     FROM change_events WHERE ${where.join(' AND ')}
     ORDER BY ts::date DESC, important DESC,
       CASE kind WHEN 'kev_added' THEN 0 WHEN 'health' THEN 1 WHEN 'log' THEN 2 WHEN 'host_state' THEN 3 WHEN 'vuln_new' THEN 4
                 WHEN 'system_new' THEN 5 WHEN 'vuln_resolved' THEN 6 WHEN 'feed' THEN 7 ELSE 8 END, ts DESC
     LIMIT 2000`,
    params,
  );
  const map = new Map<string, DayGroup>();
  for (const r of rows) {
    const g = map.get(r.day) ?? { day: r.day, items: [] };
    g.items.push(r);
    map.set(r.day, g);
  }
  return [...map.values()];
}

export const KIND_ICON: Record<string, string> = {
  kev_added: '🔴', vuln_new: '🆕', vuln_resolved: '✅', system_new: '🧩', host_state: '🖥', log: '📜', feed: '📡', health: '⚠️', ops: '👤',
};

// Days without any events between two listed days collapse into one "no change" line.
export function withGaps(groups: DayGroup[], days: number): ({ type: 'day'; g: DayGroup } | { type: 'gap'; from: string; to: string })[] {
  const out: ({ type: 'day'; g: DayGroup } | { type: 'gap'; from: string; to: string })[] = [];
  const has = new Map(groups.map((g) => [g.day, g]));
  let gapStart: string | null = null;
  let gapEnd: string | null = null;
  for (let i = 0; i < days; i++) {
    const d = new Date(Date.now() - i * 86400_000).toLocaleDateString('sv-SE');
    const g = has.get(d);
    if (g) {
      if (gapStart) out.push({ type: 'gap', from: gapEnd!, to: gapStart });
      gapStart = gapEnd = null;
      out.push({ type: 'day', g });
    } else {
      if (!gapStart) gapStart = d;
      gapEnd = d;
    }
  }
  if (gapStart) out.push({ type: 'gap', from: gapEnd!, to: gapStart });
  return out;
}
