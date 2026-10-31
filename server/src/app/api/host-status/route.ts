import { requireUser } from '@/lib/auth';
import { q1 } from '@/lib/db';

// Lightweight polling endpoint for the "対処を確認" button: is the host's control channel live, and
// when did its last report arrive? The client polls this to know the moment a fresh report lands.
export async function GET(req: Request) {
  await requireUser();
  const id = new URL(req.url).searchParams.get('id') ?? '';
  if (!/^[0-9a-f-]{36}$/.test(id)) return Response.json({ error: 'bad id' }, { status: 400 });
  const h = await q1<{ last_seen_at: Date | null; ws_seen_at: Date | null; collect_requested: boolean }>(
    'SELECT last_seen_at, ws_seen_at, collect_requested FROM hosts WHERE id=$1', [id]);
  if (!h) return Response.json({ error: 'not found' }, { status: 404 });
  const online = !!h.ws_seen_at && Date.now() - new Date(h.ws_seen_at).getTime() < 75_000;
  return Response.json({
    online,
    lastSeenAt: h.last_seen_at,
    collectRequested: h.collect_requested,
  });
}
