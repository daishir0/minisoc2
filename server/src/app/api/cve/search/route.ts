import { currentUser } from '@/lib/auth';
import { searchCves } from '@/lib/cvelookup';

export async function GET(req: Request) {
  if (!(await currentUser())) return Response.json({ error: 'unauthorized' }, { status: 401 });
  const qv = new URL(req.url).searchParams.get('q') ?? '';
  return Response.json(await searchCves(qv));
}
