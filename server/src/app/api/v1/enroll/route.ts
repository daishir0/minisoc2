import { BodyError, clientIp, rateLimited, readJson } from '@/lib/body';
import { enroll } from '@/lib/ingest';

export async function POST(req: Request) {
  if (rateLimited(`enroll:${clientIp(req)}`, 10, 10 * 60_000)) return Response.json({ error: 'too many attempts' }, { status: 429 });
  try {
    const b = await readJson<{ token?: string; hostname?: string; platform?: string; agentVersion?: string }>(req);
    if (!b.token) return Response.json({ error: 'token required' }, { status: 400 });
    const r = await enroll(String(b.token), String(b.hostname ?? ''), String(b.platform ?? ''), String(b.agentVersion ?? ''));
    if (!r) return Response.json({ error: 'invalid, used or expired enroll token' }, { status: 403 });
    return Response.json(r);
  } catch (e) {
    if (e instanceof BodyError) return Response.json({ error: e.message }, { status: e.status });
    throw e;
  }
}
