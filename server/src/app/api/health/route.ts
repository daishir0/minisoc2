import { q1 } from '@/lib/db';

export async function GET() {
  await q1('SELECT 1');
  return Response.json({ ok: true });
}
