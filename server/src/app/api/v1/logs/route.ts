import { BodyError, clientIp, readJson } from '@/lib/body';
import { authenticateHost, hostIpAllowed, recordHostIp, rejectIpAlert } from '@/lib/ingest';
import { ingestLogs } from '@/lib/logs';
import type { LogBatch } from '@/lib/payload';

export async function POST(req: Request) {
  const host = await authenticateHost(req.headers.get('authorization'));
  if (!host) return Response.json({ error: 'unauthorized' }, { status: 401 });
  const ip = clientIp(req);
  await recordHostIp(host.id, ip);
  if (!(await hostIpAllowed(host, ip))) { await rejectIpAlert(host, ip); return Response.json({ error: 'source address not allowed' }, { status: 403 }); }
  try {
    const b = await readJson<LogBatch>(req);
    if (b.schema !== 1 || !Array.isArray(b.entries)) return Response.json({ error: 'unsupported log schema' }, { status: 400 });
    if (b.entries.length > 50_000) return Response.json({ error: 'too many entries in one batch (max 50000)' }, { status: 413 });
    return Response.json({ ok: true, ...(await ingestLogs(host, b)) });
  } catch (e) {
    if (e instanceof BodyError) return Response.json({ error: e.message }, { status: e.status });
    throw e;
  }
}
