// Change timeline: events are recorded as they happen; daily snapshots keep the trend forever.
import { q } from './db';

export interface ChangeEvent {
  hostId?: string | null;
  systemRoot?: string | null;
  kind: 'vuln_new' | 'vuln_resolved' | 'kev_added' | 'system_new' | 'host_state' | 'log' | 'feed' | 'health' | 'ops';
  important: boolean; // KEV / critical / intrusion sign / monitoring health
  count?: number;
  title: string;
  detail?: string;
}

export async function recordEvent(e: ChangeEvent): Promise<void> {
  await q('INSERT INTO change_events(host_id, system_root, kind, important, count, title, detail) VALUES ($1,$2,$3,$4,$5,$6,$7)', [
    e.hostId ?? null, e.systemRoot ?? null, e.kind, e.important, e.count ?? 1, e.title.replace(/\u0000/g, '').slice(0, 500), (e.detail ?? '').slice(0, 2000),
  ]);
}

// Today's open findings per system for one host (replaces today's rows).
export async function snapshot(hostId: string): Promise<void> {
  await q('DELETE FROM daily_snapshots WHERE day=current_date AND host_id=$1', [hostId]);
  await q(
    `INSERT INTO daily_snapshots(day, host_id, system_root, kev, critical, high, medium, low)
     SELECT current_date, host_id, sys, count(*) FILTER (WHERE kev), count(*) FILTER (WHERE NOT kev AND severity='critical'),
       count(*) FILTER (WHERE NOT kev AND severity='high'), count(*) FILTER (WHERE NOT kev AND severity='medium'), count(*) FILTER (WHERE NOT kev AND severity='low')
     FROM findings, unnest(CASE WHEN cardinality(systems) = 0 THEN ARRAY['__os__'] ELSE systems END) AS sys
     WHERE host_id=$1 AND status='open' GROUP BY host_id, sys`,
    [hostId],
  );
}
