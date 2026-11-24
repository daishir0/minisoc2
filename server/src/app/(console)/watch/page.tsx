import { Breadcrumbs, CRUMB } from '@/components/Breadcrumbs';
import Link from 'next/link';
import { ActionForm } from '@/components/ActionForm';
import { Card, Sev, ago, vulnLink } from '@/components/ui';
import { q } from '@/lib/db';
import { addWatch, removeWatch } from '../actions';

const STATUS_LABEL: Record<string, string> = { watching: '監視中', resolved: '解決済み', archived: 'アーカイブ' };

export default async function WatchPage({ searchParams }: { searchParams: Promise<Record<string, string | undefined>> }) {
  const view = (await searchParams).view === 'archived' ? 'archived' : 'active';
  const rows = await q<{ cve: string; note: string; created_at: Date; status: string; resolved_at: Date | null; open: string; resolved: string; hosts: string | null; summary: string | null; severity: string | null }>(
    `SELECT w.cve, w.note, w.created_at, w.status, w.resolved_at,
       count(f.id) FILTER (WHERE f.status='open') AS open, count(f.id) FILTER (WHERE f.status='resolved') AS resolved,
       string_agg(DISTINCT h.name, ', ') FILTER (WHERE f.status='open') AS hosts,
       coalesce(nullif((SELECT data->'nvd'->>'description' FROM cve_lookups cl WHERE cl.cve=w.cve), ''),
                nullif((SELECT data->'ghsa'->0->>'summary' FROM cve_lookups cl WHERE cl.cve=w.cve), ''),
                (SELECT summary FROM vulns v WHERE v.id=w.cve OR w.cve = ANY(v.aliases) LIMIT 1)) AS summary,
       coalesce(lower(nullif((SELECT data->'nvd'->>'severity' FROM cve_lookups cl WHERE cl.cve=w.cve), '')),
                (SELECT severity FROM vulns v WHERE v.id=w.cve OR w.cve = ANY(v.aliases) LIMIT 1)) AS severity
     FROM watch_cves w
       LEFT JOIN findings f ON (f.vuln_id=w.cve OR EXISTS (SELECT 1 FROM vulns v WHERE v.id=f.vuln_id AND w.cve = ANY(v.aliases)))
       LEFT JOIN hosts h ON h.id=f.host_id
     WHERE w.status ${view === 'archived' ? "= 'archived'" : "<> 'archived'"}
     GROUP BY w.cve ORDER BY (w.status='watching' AND count(f.id) FILTER (WHERE f.status='open')>0) DESC, w.created_at DESC`,
  );
  const counts = await q<{ status: string; n: string }>('SELECT status, count(*) AS n FROM watch_cves GROUP BY status');
  const cnt = (s: string) => Number(counts.find((c) => c.status === s)?.n ?? 0);
  const active = cnt('watching') + cnt('resolved');

  return (
    <>
      <Breadcrumbs items={[CRUMB.home, { label: 'CVE監視' }]} />
      <Card title="CVEを監視する">
        <p className="mb-3 text-sm text-muted">監視中のCVEは、どのホストに出ても必ず通知し、修正が届いた時にも通知します。対処が済んで全ホストで解消すると自動的に「解決済み」になり、無駄な再照合・外部照会を止めます（再発すれば自動で監視に戻ります）。もう不要なら「アーカイブ」で履歴を残したまま停止できます。</p>
        <ActionForm action={addWatch} className="flex flex-wrap gap-2">
          <input name="cve" className="input w-56" placeholder="CVE-2026-12345" required />
          <input name="note" className="input w-72" placeholder="メモ（例：php2shell）" />
          <button className="btn">監視する</button>
        </ActionForm>
      </Card>

      <Card title={view === 'archived' ? `アーカイブ（${cnt('archived')}件）` : `監視中・解決済み（${active}件）`}
        right={<div className="flex gap-2 text-xs">
          <Link href="/watch" className={view === 'active' ? 'font-bold text-accent' : 'text-muted'}>有効 {active}</Link>
          <Link href="/watch?view=archived" className={view === 'archived' ? 'font-bold text-accent' : 'text-muted'}>アーカイブ {cnt('archived')}</Link>
        </div>}>
        {rows.length === 0 ? <p className="text-sm text-muted">{view === 'archived' ? 'アーカイブしたCVEはありません。' : '監視中のCVEはありません。'}</p> : (
          <div className="overflow-x-auto"><table className="tbl">
            <thead><tr><th>CVE</th><th>深刻度</th><th>概要</th><th>状態</th><th>影響ホスト</th><th>登録</th><th></th></tr></thead>
            <tbody>
              {rows.map((r) => {
                const open = Number(r.open);
                const sm = (r.summary ?? '').replace(/\s+/g, ' ').trim();
                const state = r.status === 'archived' ? 'アーカイブ' : open > 0 ? '未解消' : r.status === 'resolved' ? '解決済み' : '監視中（未検出）';
                const stateCls = open > 0 ? 'text-red-600' : r.status === 'resolved' ? 'text-green-600' : 'text-muted';
                return (
                  <tr key={r.cve}>
                    <td className="whitespace-nowrap">{vulnLink(r.cve)}{r.note && <div className="text-xs text-muted">{r.note}</div>}</td>
                    <td>{r.severity && r.severity !== 'unknown' ? <Sev s={r.severity} /> : <span className="text-xs text-muted">—</span>}</td>
                    <td className="max-w-sm"><span className="line-clamp-1 text-xs text-muted" title={sm}>{sm || '（概要情報なし）'}</span></td>
                    <td className={`whitespace-nowrap text-sm ${stateCls}`}>{state}{open > 0 && <> ({open})</>}</td>
                    <td className="text-xs">{open > 0 ? <Link className="text-accent" href={`/findings?q=${r.cve}&all=1`}>{r.hosts}</Link> : <span className="text-muted">—</span>}</td>
                    <td className="whitespace-nowrap text-xs text-muted">{ago(r.created_at)}</td>
                    <td className="whitespace-nowrap">
                      <div className="flex gap-2 text-xs">
                        {r.status === 'archived' ? (
                          <form action={removeWatch}><input type="hidden" name="cve" value={r.cve} /><input type="hidden" name="op" value="unarchive" /><button className="text-accent">監視に戻す</button></form>
                        ) : (
                          <form action={removeWatch}><input type="hidden" name="cve" value={r.cve} /><input type="hidden" name="op" value="archive" /><button className="text-accent">アーカイブ</button></form>
                        )}
                        <form action={removeWatch}><input type="hidden" name="cve" value={r.cve} /><input type="hidden" name="op" value="delete" /><button className="text-muted hover:text-red-600">削除</button></form>
                      </div>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table></div>
        )}
      </Card>
    </>
  );
}
