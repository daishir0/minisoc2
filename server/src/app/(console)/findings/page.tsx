import { Breadcrumbs, CRUMB } from '@/components/Breadcrumbs';
import Link from 'next/link';
import { ExploreTabs } from '@/components/ExploreTabs';
import { Card, Kev, SEV_LABEL, Sev, ago, vulnLink } from '@/components/ui';
import { q } from '@/lib/db';
import { VEX_JUSTIFICATIONS, VEX_LABEL } from '@/lib/vex';
import { suppressFinding } from '../actions';

const PAGE = 100;
const STATUS_LABEL: Record<string, string> = { open: '未対応', suppressed: '影響なし（VEX）', resolved: '解消済み' };

export default async function FindingsPage({ searchParams }: { searchParams: Promise<Record<string, string | undefined>> }) {
  const sp = await searchParams;
  const status = ['open', 'suppressed', 'resolved'].includes(sp.status ?? '') ? sp.status! : 'open';
  const where = ['f.status=$1'];
  const params: unknown[] = [status];
  const showAll = sp.all === '1' || !!sp.severity;
  if (sp.severity) { params.push(sp.severity); where.push(`f.severity=$${params.length}`); }
  else if (!showAll && sp.kev !== '1') where.push("(f.kev OR f.severity='critical')");
  if (sp.host && /^[0-9a-f-]{36}$/.test(sp.host)) { params.push(sp.host); where.push(`f.host_id=$${params.length}`); }
  if (sp.kev === '1') where.push('f.kev');
  if (sp.source) { params.push(sp.source); where.push(`f.source=$${params.length}`); }
  if (sp.system) { params.push(sp.system); where.push(`$${params.length} = ANY(f.systems)`); }
  if (sp.q) { params.push(`%${sp.q}%`); where.push(`(f.vuln_id ILIKE $${params.length} OR f.pkg ILIKE $${params.length})`); }
  const page = Math.max(0, Number(sp.page ?? 0) || 0);
  const total = Number((await q<{ n: string }>(`SELECT count(*) AS n FROM findings f WHERE ${where.join(' AND ')}`, params))[0].n);
  const rows = await q<{
    id: string; host_id: string; host: string; vuln_id: string; ecosystem: string; pkg: string; version: string; fixed: string;
    severity: string; kev: boolean; source: string; first_seen: Date; summary: string | null; suppress_reason: string | null; suppress_note: string | null; cvss: string | null;
  }>(
    `SELECT f.*, h.name AS host, (SELECT v.summary FROM vulns v WHERE v.id=f.vuln_id OR f.vuln_id = ANY(v.aliases) LIMIT 1) AS summary
     FROM findings f JOIN hosts h ON h.id=f.host_id WHERE ${where.join(' AND ')}
     ORDER BY f.kev DESC, CASE f.severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END, f.cvss DESC NULLS LAST, f.first_seen DESC
     LIMIT ${PAGE} OFFSET ${page * PAGE}`,
    params,
  );
  const link = (patch: Record<string, string | undefined>) => {
    const u = new URLSearchParams(Object.entries({ ...sp, ...patch }).filter(([, v]) => v) as [string, string][]);
    return `/findings?${u}`;
  };

  return (
    <>
      <Breadcrumbs items={[CRUMB.home, { label: "検知" }]} />
      <ExploreTabs />
    <Card title={`脆弱性：${STATUS_LABEL[status]} ${total}件${!showAll && sp.kev !== '1' ? '（KEV・緊急）' : ''}`}>
      {!showAll && (
        <p className="mb-3 text-xs text-muted">
          KEV と緊急（CVSS 9.0以上）だけを表示しています。<Link className="text-accent" href={link({ all: '1' })}>すべての深刻度を表示</Link>
        </p>
      )}
      {showAll && !sp.severity && <p className="mb-3 text-xs text-muted">すべての深刻度を表示しています。<Link className="text-accent" href={link({ all: undefined })}>KEV・緊急だけに戻す</Link></p>}
      <form className="mb-4 grid grid-cols-2 gap-2 text-sm sm:flex sm:flex-wrap" action="/findings">
        <select name="status" defaultValue={status} className="input sm:w-auto"><option value="open">未対応</option><option value="suppressed">影響なし（VEX）</option><option value="resolved">解消済み</option></select>
        <select name="severity" defaultValue={sp.severity ?? ''} className="input sm:w-auto"><option value="">深刻度：すべて</option>{['critical', 'high', 'medium', 'low', 'unknown'].map((s) => <option key={s} value={s}>{SEV_LABEL[s]}</option>)}</select>
        <select name="source" defaultValue={sp.source ?? ''} className="input sm:w-auto"><option value="">種別：すべて</option><option value="os-advisory">OSパッケージ</option><option value="osv">アプリ依存</option></select>
        <label className="flex items-center gap-1"><input type="checkbox" name="kev" value="1" defaultChecked={sp.kev === '1'} /> KEVのみ</label>
        <input name="q" defaultValue={sp.q ?? ''} placeholder="CVE またはパッケージ名" className="input col-span-2 sm:w-48" />
        {sp.host && <input type="hidden" name="host" value={sp.host} />}
        {sp.system && <input type="hidden" name="system" value={sp.system} />}
        {sp.all && <input type="hidden" name="all" value="1" />}
        <button className="btn">絞り込み</button>
        {sp.host && <Link href={link({ host: undefined, system: undefined })} className="btn-ghost">全ホスト</Link>}
        {sp.system && <Link href={link({ system: undefined })} className="btn-ghost col-span-2 truncate">システム：{sp.system === '__os__' ? 'OSパッケージ' : sp.system.split('/').pop()} ✕</Link>}
        {status === 'suppressed' && <a href={`/api/vex${sp.host ? `?host=${sp.host}` : ''}`} className="btn-ghost">VEX（CycloneDX）を出力</a>}
      </form>
      {/* phones: one card per finding */}
      <ul className="divide-y divide-line md:hidden">
        {rows.map((f) => (
          <li key={f.id} className="py-3 text-sm">
            <div className="flex flex-wrap items-center gap-2"><Sev s={f.severity} />{f.kev && <Kev />}{vulnLink(f.vuln_id)}{f.cvss && <span className="text-xs text-muted">CVSS {f.cvss}</span>}</div>
            {f.summary && <div className="mt-1 text-xs text-muted">{f.summary}</div>}
            <div className="mt-1 break-all font-mono text-xs">{f.pkg} <span className="text-muted">{f.version.slice(0, 80)}</span></div>
            {f.fixed && <div className="break-all text-xs text-muted">修正版：{f.fixed.slice(0, 80)}</div>}
            <div className="mt-1 text-xs text-muted"><Link className="text-accent" href={`/hosts/${f.host_id}`}>{f.host}</Link> · {ago(f.first_seen)}</div>
            {status === 'open' && (
              <details className="mt-1">
                <summary className="cursor-pointer text-xs text-accent">影響なしにする…</summary>
                <form action={suppressFinding} className="mt-2 space-y-2">
                  <input type="hidden" name="id" value={f.id} />
                  <select name="reason" className="input" required>{VEX_JUSTIFICATIONS.map((j) => <option key={j} value={j}>{VEX_LABEL[j]}</option>)}</select>
                  <input name="note" className="input" placeholder="判断の理由（メモ）" />
                  <button className="btn-ghost">影響なしとして記録</button>
                </form>
              </details>
            )}
            {status === 'suppressed' && (
              <form action={suppressFinding} className="mt-1 text-xs">
                <span className="text-muted">{VEX_LABEL[f.suppress_reason ?? ''] ?? f.suppress_reason}{f.suppress_note ? `: ${f.suppress_note}` : ''}</span>
                <input type="hidden" name="id" value={f.id} /><input type="hidden" name="undo" value="1" />
                <button className="ml-2 text-accent">未対応に戻す</button>
              </form>
            )}
          </li>
        ))}
      </ul>
      <div className="hidden overflow-x-auto md:block">
        <table className="tbl">
          <thead><tr><th>深刻度</th><th>脆弱性</th><th>パッケージ</th><th>修正版</th><th>ホスト</th><th>検出</th><th></th></tr></thead>
          <tbody>
            {rows.map((f) => (
              <tr key={f.id}>
                <td className="whitespace-nowrap"><Sev s={f.severity} /> {f.kev && <Kev />}{f.cvss && <div className="text-xs text-muted">CVSS {f.cvss}</div>}</td>
                <td>{vulnLink(f.vuln_id)}{f.summary && <div className="max-w-md text-xs text-muted">{f.summary}</div>}</td>
                <td><div className="font-mono text-xs">{f.pkg}</div><div className="max-w-xs truncate text-xs text-muted" title={f.version}>{f.ecosystem} {f.version}</div></td>
                <td className="max-w-[12rem] truncate font-mono text-xs" title={f.fixed}>{f.fixed || '-'}</td>
                <td><Link className="text-accent" href={`/hosts/${f.host_id}`}>{f.host}</Link></td>
                <td className="whitespace-nowrap text-xs">{ago(f.first_seen)}</td>
                <td>
                  {status === 'open' && (
                    <details>
                      <summary className="cursor-pointer text-xs text-accent">影響なしにする…</summary>
                      <form action={suppressFinding} className="mt-2 w-64 space-y-2">
                        <input type="hidden" name="id" value={f.id} />
                        <select name="reason" className="input" required>{VEX_JUSTIFICATIONS.map((j) => <option key={j} value={j}>{VEX_LABEL[j]}</option>)}</select>
                        <input name="note" className="input" placeholder="判断の理由（メモ）" />
                        <button className="btn-ghost">影響なしとして記録</button>
                      </form>
                    </details>
                  )}
                  {status === 'suppressed' && (
                    <form action={suppressFinding} className="text-xs">
                      <div className="text-muted">{VEX_LABEL[f.suppress_reason ?? ''] ?? f.suppress_reason}{f.suppress_note ? `: ${f.suppress_note}` : ''}</div>
                      <input type="hidden" name="id" value={f.id} /><input type="hidden" name="undo" value="1" />
                      <button className="text-accent">未対応に戻す</button>
                    </form>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <div className="mt-4 flex gap-2 text-sm">
        {page > 0 && <Link className="btn-ghost" href={link({ page: String(page - 1) })}>前へ</Link>}
        {(page + 1) * PAGE < total && <Link className="btn-ghost" href={link({ page: String(page + 1) })}>次へ</Link>}
        <span className="ml-auto text-muted">{page + 1} / {Math.max(1, Math.ceil(total / PAGE))} ページ</span>
      </div>
    </Card>
    </>
  );
}
