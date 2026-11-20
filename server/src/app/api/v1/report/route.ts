import { BodyError, clientIp, readJson } from '@/lib/body';
import { authenticateHost, hostIpAllowed, ingestReport, recordHostIp, rejectIpAlert } from '@/lib/ingest';
import type { Report } from '@/lib/payload';

export async function POST(req: Request) {
  const host = await authenticateHost(req.headers.get('authorization'));
  if (!host) return Response.json({ error: 'unauthorized' }, { status: 401 });
  const ip = clientIp(req);
  await recordHostIp(host.id, ip);
  if (!(await hostIpAllowed(host, ip))) { await rejectIpAlert(host, ip); return Response.json({ error: 'source address not allowed' }, { status: 403 }); }
  try {
    const r = await readJson<Report>(req);
    if (r.schema !== 1 || !r.host || !Array.isArray(r.packages) || !r.state) {
      return Response.json({ error: 'unsupported report schema' }, { status: 400 });
    }
    const res = await ingestReport(host, r);
    return Response.json({ ok: true, ...res });
  } catch (e) {
    if (e instanceof BodyError) return Response.json({ error: e.message }, { status: e.status });
    throw e;
  }
}
