import { currentUser } from '@/lib/auth';
import { searchCves } from '@/lib/cvelookup';
import { q } from '@/lib/db';

// Header search: CVEs, hosts, systems and packages in one list.
export async function GET(req: Request) {
  if (!(await currentUser())) return Response.json({ error: 'unauthorized' }, { status: 401 });
  const term = (new URL(req.url).searchParams.get('q') ?? '').trim().slice(0, 100);
  if (term.length < 2) return Response.json([]);
  const like = `%${term.replace(/[%_]/g, '')}%`;
  const [cves, hosts, systems, pkgs] = await Promise.all([
    /^cve-?\d/i.test(term) ? searchCves(term) : Promise.resolve([]),
    q<{ id: string; name: string; os_name: string }>('SELECT id, name, os_name FROM hosts WHERE name ILIKE $1 OR hostname ILIKE $1 ORDER BY name LIMIT 5', [like]),
    q<{ id: number; name: string; host: string }>('SELECT s.id, s.name, h.name AS host FROM systems s JOIN hosts h ON h.id=s.host_id WHERE s.name ILIKE $1 OR s.root ILIKE $1 ORDER BY s.name LIMIT 6', [like]),
    term.length >= 3
      ? q<{ ecosystem: string; name: string; hosts: string }>(
          `SELECT p.ecosystem, p.name, string_agg(DISTINCT h.name, '、') AS hosts FROM host_packages p JOIN hosts h ON h.id=p.host_id
           WHERE p.name ILIKE $1 GROUP BY p.ecosystem, p.name ORDER BY length(p.name) LIMIT 6`, [`${term.replace(/[%_]/g, '')}%`])
      : Promise.resolve([]),
  ]);
  return Response.json([
    ...cves.slice(0, 6).map((c) => ({ type: 'CVE', label: c.id, sub: '', href: `/cve/${c.id}` })),
    ...(/^cve-\d{4}-\d{4,}$/i.test(term) && !cves.some((c) => c.id === term.toUpperCase()) ? [{ type: 'CVE', label: term.toUpperCase(), sub: '外部の情報を照会', href: `/cve/${term.toUpperCase()}` }] : []),
    ...hosts.map((h) => ({ type: 'ホスト', label: h.name, sub: h.os_name, href: `/hosts/${h.id}` })),
    ...systems.map((s) => ({ type: 'システム', label: s.name, sub: s.host, href: `/systems/${s.id}` })),
    ...pkgs.map((p) => ({ type: 'パッケージ', label: p.name, sub: `${p.ecosystem}・${p.hosts}`, href: `/findings?all=1&q=${encodeURIComponent(p.name)}` })),
  ]);
}
