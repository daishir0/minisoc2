import { clientIp } from '@/lib/body';
import { authenticateHost, hostIpAllowed } from '@/lib/ingest';
import { q1 } from '@/lib/db';

// Lightweight check-in: the agent polls this often (cheap). It records the check-in, and if the
// console queued an on-demand collection it returns collect:true once (the flag is consumed here).
export async function GET(req: Request) {
  const host = await authenticateHost(req.headers.get('authorization'));
  if (!host) return Response.json({ error: 'unauthorized' }, { status: 401 });
  if (!(await hostIpAllowed(host, clientIp(req)))) return Response.json({ error: 'source address not allowed' }, { status: 403 });
  const r = await q1<{ collect: boolean }>(
    `WITH prev AS (SELECT collect_requested AS c FROM hosts WHERE id=$1)
     UPDATE hosts SET last_checkin_at=now(), collect_requested=false WHERE id=$1
     RETURNING (SELECT c FROM prev) AS collect`,
    [host.id]);
  return Response.json({ collect: !!r?.collect });
}
