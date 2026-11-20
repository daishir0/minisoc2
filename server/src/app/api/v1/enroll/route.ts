import { BodyError, clientIp, rateLimited, readJson } from '@/lib/body';
import { enroll, enrollIpAllowed, recordHostIp } from '@/lib/ingest';

export async function POST(req: Request) {
  const ip = clientIp(req);
  if (rateLimited(`enroll:${ip}`, 10, 10 * 60_000)) return Response.json({ error: 'too many attempts' }, { status: 429 });
  if (!(await enrollIpAllowed(ip))) return Response.json({ error: 'source address not allowed' }, { status: 403 });
  try {
    const b = await readJson<{ token?: string; hostname?: string; platform?: string; agentVersion?: string }>(req);
    if (!b.token) return Response.json({ error: 'token required' }, { status: 400 });
    const r = await enroll(String(b.token), String(b.hostname ?? ''), String(b.platform ?? ''), String(b.agentVersion ?? ''));
    if (!r) return Response.json({ error: 'invalid, used or expired enroll token' }, { status: 403 });
    await recordHostIp(r.hostId, ip); // first observed address, so the console can offer to pin it
    return Response.json(r);
  } catch (e) {
    if (e instanceof BodyError) return Response.json({ error: e.message }, { status: e.status });
    throw e;
  }
}
