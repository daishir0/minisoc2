import { BodyError, readJson } from '@/lib/body';
import { authenticateHost, ingestReport } from '@/lib/ingest';
import type { Report } from '@/lib/payload';

export async function POST(req: Request) {
  const host = await authenticateHost(req.headers.get('authorization'));
  if (!host) return Response.json({ error: 'unauthorized' }, { status: 401 });
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
