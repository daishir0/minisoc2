import { currentUser } from '@/lib/auth';
import { q } from '@/lib/db';
import { CAT } from '@/lib/logcat';

// Raw log lines for the /logs raw viewer, fetched client-side so the filter can change in place (no reload).
// Supports host / source / category / vhost / HTTP-status (class or exact) / rule (lines that triggered a
// detection rule) / specific day / relative hours / free text.
export async function GET(req: Request) {
  if (!(await currentUser())) return Response.json({ error: 'unauthorized' }, { status: 401 });
  const sp = new URL(req.url).searchParams;
  const host = sp.get('host'); const hostOk = host && /^[0-9a-f-]{36}$/.test(host) ? host : undefined;
  const hours = Math.min(24 * 365, Math.max(1, Number(sp.get('hours') ?? 24) || 24));
  const day = sp.get('day'); const dayOk = day && /^\d{4}-\d{2}-\d{2}$/.test(day) ? day : undefined;
  const rule = sp.get('rule'); const ruleOk = rule && /^[\w:.-]{1,80}$/.test(rule) ? rule : undefined;

  type Row = { ts: Date | null; received_at: Date; source: string; message: string; host: string };
  let rows: Row[];
  if (ruleOk) {
    const p: unknown[] = [ruleOk]; let w = 'lh.rule_id=$1';
    if (hostOk) { p.push(hostOk); w += ` AND lh.host_id=$${p.length}`; }
    if (dayOk) { p.push(dayOk); w += ` AND (lh.ts AT TIME ZONE 'UTC')::date = $${p.length}::date`; }
    else { p.push(String(hours)); w += ` AND lh.ts > now() - ($${p.length} || ' hours')::interval`; }
    rows = await q<Row>(`SELECT lh.ts, lh.ts AS received_at, 'rule:' || lh.rule_id AS source, lh.sample AS message, h.name AS host
      FROM log_hits lh JOIN hosts h ON h.id=lh.host_id WHERE ${w} ORDER BY lh.ts DESC LIMIT 300`, p);
  } else {
    const where: string[] = []; const p: unknown[] = [];
    if (hostOk) { p.push(hostOk); where.push(`l.host_id=$${p.length}`); }
    const source = sp.get('source'); if (source) { p.push(source); where.push(`l.source=$${p.length}`); }
    const cat = sp.get('cat'); if (cat && cat in CAT) where.push(`(${CAT[cat as keyof typeof CAT]})`);
    const vhost = sp.get('vhost'); if (vhost && /^[\w.*-]{1,120}$/.test(vhost)) { p.push(`%${vhost}%`); where.push(`l.source ILIKE $${p.length}`); }
    const status = sp.get('status'); if (status && /^[1-5](xx|\d\d)$/.test(status)) { p.push(status.endsWith('xx') ? `" ${status[0]}[0-9][0-9] ` : `" ${status} `); where.push(`l.message ~ $${p.length}`); }
    const text = sp.get('q'); if (text) { p.push(`%${text}%`); where.push(`l.message ILIKE $${p.length}`); }
    if (dayOk) { p.push(dayOk); where.push(`(coalesce(l.ts, l.received_at) AT TIME ZONE 'UTC')::date = $${p.length}::date`); }
    else { p.push(String(hours)); where.push(`l.received_at > now() - ($${p.length} || ' hours')::interval`); }
    rows = await q<Row>(`SELECT l.ts, l.received_at, l.source, l.message, h.name AS host FROM raw_logs l JOIN hosts h ON h.id=l.host_id
      WHERE ${where.join(' AND ')} ORDER BY l.received_at DESC, l.ts DESC NULLS LAST LIMIT 300`, p);
  }
  return Response.json({ lines: rows });
}
