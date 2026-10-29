import { Breadcrumbs, CRUMB } from '@/components/Breadcrumbs';
import Link from 'next/link';
import { ActionForm } from '@/components/ActionForm';
import { Card, ago, vulnLink } from '@/components/ui';
import { q } from '@/lib/db';
import { addWatch, removeWatch } from '../actions';

export default async function WatchPage() {
  const rows = await q<{ cve: string; note: string; created_at: Date; open: string; resolved: string; hosts: string | null }>(
    `SELECT w.cve, w.note, w.created_at,
       count(f.id) FILTER (WHERE f.status='open') AS open, count(f.id) FILTER (WHERE f.status='resolved') AS resolved,
       string_agg(DISTINCT h.name, ', ') FILTER (WHERE f.status='open') AS hosts
     FROM watch_cves w LEFT JOIN findings f ON f.vuln_id=w.cve LEFT JOIN hosts h ON h.id=f.host_id
     GROUP BY w.cve ORDER BY w.created_at DESC`,
  );
  return (
    <>
      <Breadcrumbs items={[CRUMB.home, { label: "CVE監視" }]} />
      <Card title="CVEを監視する">
        <p className="mb-3 text-sm text-muted">監視中のCVEは、どのホストに出ても必ず通知し、修正が届いた時にも通知します（特定の脆弱性を、全ホストに修正が行き渡るまで追跡する用途）。</p>
        <ActionForm action={addWatch} className="flex flex-wrap gap-2">
          <input name="cve" className="input w-56" placeholder="CVE-2026-12345" required />
          <input name="note" className="input w-72" placeholder="メモ（例：php2shell）" />
          <button className="btn">監視する</button>
        </ActionForm>
      </Card>
      <Card title={`監視中（${rows.length}件）`}>
        <table className="tbl"><thead><tr><th>CVE</th><th>メモ</th><th>現在影響あり</th><th>解消済み</th><th>登録</th><th></th></tr></thead><tbody>
          {rows.map((r) => (
            <tr key={r.cve}>
              <td>{vulnLink(r.cve)}</td><td>{r.note}</td>
              <td className={Number(r.open) ? 'text-red-600' : 'text-green-600'}>{Number(r.open) ? <Link href={`/findings?q=${r.cve}`}>{r.open} ({r.hosts})</Link> : 'なし'}</td>
              <td>{r.resolved}</td><td className="text-xs">{ago(r.created_at)}</td>
              <td><form action={removeWatch}><input type="hidden" name="cve" value={r.cve} /><button className="text-xs text-accent">解除</button></form></td>
            </tr>
          ))}
        </tbody></table>
      </Card>
    </>
  );
}
