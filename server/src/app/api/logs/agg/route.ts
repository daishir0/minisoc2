import { currentUser } from '@/lib/auth';
import { aggregate } from '@/lib/logagg';
import { MEASURES, type DimKey, type MeasureKey } from '@/lib/logexplore';

// Aggregated log data for the explorer panel: ?measure=&dim=&range=&host=&cat=&vhost=&rule=&source=&day=
export async function GET(req: Request) {
  if (!(await currentUser())) return Response.json({ error: 'unauthorized' }, { status: 401 });
  const sp = new URL(req.url).searchParams;
  const md = MEASURES.find((m) => m.k === sp.get('measure'));
  if (!md) return Response.json({ error: 'bad measure' }, { status: 400 });
  const dim = sp.get('dim') as DimKey;
  if (!md.dims.includes(dim)) return Response.json({ error: 'bad dim for measure' }, { status: 400 });
  const days = Math.min(90, Math.max(1, Number(sp.get('range') ?? 30) || 30));
  const filters: Record<string, string | undefined> = {};
  for (const k of ['host', 'cat', 'vhost', 'rule', 'source', 'day']) { const v = sp.get(k); if (v) filters[k] = v; }
  const r = await aggregate({ measure: md.k as MeasureKey, dim, days, filters });
  return Response.json(r);
}
