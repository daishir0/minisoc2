'use client';

import { useEffect, useRef, useState } from 'react';
import { Masked } from '@/components/Mask';

// Fleet-wide SBOM browser: debounced server-side search over /api/components with host / ecosystem /
// layer / license / vuln filters, a reverse-lookup "used by" column, and pagination. Responsive (table on
// desktop, cards on phones). The per-project SbomTable stays for the small, single-project view.
interface Comp { pkg: string; version: string; eco: string; license: string; cls: 'strong' | 'weak' | 'perm' | 'unk'; purl: string; vuln: '' | 'kev' | 'crit'; nhosts: number; hosts: string[]; nprojects: number; projects: string[] }
const CLS: Record<Comp['cls'], [string, string]> = {
  strong: ['bg-red-100 text-red-700 dark:bg-red-950 dark:text-red-200', '強'],
  weak: ['bg-amber-100 text-amber-800 dark:bg-amber-950 dark:text-amber-200', '弱'],
  perm: ['bg-green-100 text-green-700 dark:bg-green-950 dark:text-green-200', '寛容'],
  unk: ['bg-bg text-muted', '不明'],
};
function Vuln({ v }: { v: Comp['vuln'] }) {
  if (v === 'kev') return <span className="rounded bg-red-600 px-1.5 py-0.5 text-[10px] font-bold text-white">KEV</span>;
  if (v === 'crit') return <span className="rounded bg-red-100 px-1.5 py-0.5 text-[10px] font-bold text-red-700 dark:bg-red-950 dark:text-red-200">緊急</span>;
  return <span className="text-xs text-muted">—</span>;
}
function Lic({ d }: { d: Comp }) { const [c, l] = CLS[d.cls]; return <><span className={`rounded px-1.5 py-0.5 text-[10px] font-bold ${c}`}>{l}</span> <span className="font-mono text-xs">{d.license}</span></>; }
function Uses({ d }: { d: Comp }) {
  return <span className="text-xs">{d.hosts.map((h, i) => <span key={i}>{i > 0 && '、'}<Masked kind="host">{h}</Masked></span>)}{d.nhosts > d.hosts.length && <span className="text-muted"> 他{d.nhosts - d.hosts.length}</span>}</span>;
}
function Projects({ d }: { d: Comp }) {
  if (!d.projects.length) return <span className="text-xs text-muted">—</span>;
  return <span className="text-xs">{d.projects.map((p, i) => <span key={i}>{i > 0 && '、'}<Masked kind="system">{p}</Masked></span>)}{d.nprojects > d.projects.length && <span className="text-muted"> 他{d.nprojects - d.projects.length}</span>}</span>;
}

export function SbomBrowser({ hosts, ecos, projects, initialLicense = '' }: { hosts: { id: string; name: string }[]; ecos: string[]; projects: { root: string; name: string; hostId: string }[]; initialLicense?: string }) {
  const [q, setQ] = useState('');
  const [host, setHost] = useState('');
  const [project, setProject] = useState('');
  const [eco, setEco] = useState('');
  const [layer, setLayer] = useState('');
  const [license, setLicense] = useState(initialLicense);
  const [vuln, setVuln] = useState('');
  const [page, setPage] = useState(0);
  const [data, setData] = useState<{ total: number; per: number; rows: Comp[] }>({ total: 0, per: 50, rows: [] });
  const [loading, setLoading] = useState(false);
  const deb = useRef<ReturnType<typeof setTimeout>>(undefined);

  const params = () => {
    const p = new URLSearchParams();
    if (q) p.set('q', q); if (host) p.set('host', host); if (project) p.set('project', project); if (eco) p.set('eco', eco);
    if (layer) p.set('layer', layer); if (license) p.set('license', license); if (vuln) p.set('vuln', vuln);
    p.set('page', String(page));
    return p;
  };
  useEffect(() => { setPage(0); }, [q, host, project, eco, layer, license, vuln]);
  useEffect(() => {
    clearTimeout(deb.current);
    deb.current = setTimeout(async () => {
      setLoading(true);
      try {
        const r = await fetch(`/api/components?${params()}`);
        if (r.ok) setData(await r.json());
      } catch { /* keep previous */ } finally { setLoading(false); }
    }, 220);
    return () => clearTimeout(deb.current);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [q, host, project, eco, layer, license, vuln, page]);

  // Project dropdown options: when a host is chosen, its projects; otherwise all (deduped by root+name).
  const projOpts = (() => {
    const src = host ? projects.filter((p) => p.hostId === host) : projects;
    const seen = new Set<string>(); const out: { root: string; name: string }[] = [];
    for (const p of src) { const k = `${p.root}\u0000${p.name}`; if (!seen.has(k)) { seen.add(k); out.push({ root: p.root, name: p.name }); } }
    return out.sort((a, b) => a.name.localeCompare(b.name));
  })();
  const chip = (on: boolean) => `rounded-full border px-2.5 py-1 text-xs font-semibold ${on ? 'border-transparent bg-accent text-white dark:text-black' : 'border-line bg-panel text-muted'}`;
  const pages = Math.max(1, Math.ceil(data.total / data.per));
  const csvHref = () => { const p = params(); p.delete('page'); p.set('format', 'csv'); return `/api/components?${p}`; };

  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center gap-2">
        <input value={q} onChange={(e) => setQ(e.target.value)} autoComplete="off" placeholder="🔍 name / purl / ライセンスで横断検索（入力即反映）" className="input min-w-[220px] flex-1" />
        <a href={csvHref()} className="btn-ghost text-xs">⬇ CSV（絞り込み）</a>
      </div>
      <div className="flex flex-wrap items-center gap-2">
        <select value={host} onChange={(e) => { setHost(e.target.value); setProject(''); }} className="input w-auto text-sm"><option value="">全ホスト</option>{hosts.map((h) => <option key={h.id} value={h.id}>{h.name}</option>)}</select>
        {projOpts.length > 0 && (
          <select value={project} onChange={(e) => setProject(e.target.value)} className="input w-auto text-sm">
            <option value="">全プロジェクト</option>
            {projOpts.map((p) => <option key={p.root} value={p.root}>{p.name}</option>)}
          </select>
        )}
        <select value={eco} onChange={(e) => setEco(e.target.value)} className="input w-auto text-sm"><option value="">全エコシステム</option>{ecos.map((e) => <option key={e} value={e}>{e}</option>)}</select>
        <select value={layer} onChange={(e) => setLayer(e.target.value)} className="input w-auto text-sm"><option value="">全レイヤ</option><option value="app">アプリ依存</option><option value="os">OS</option></select>
        <button type="button" onClick={() => setLicense(license === 'copyleft' ? '' : 'copyleft')} className={chip(license === 'copyleft')}>コピーレフトのみ</button>
        <button type="button" onClick={() => setVuln(vuln === '1' ? '' : '1')} className={chip(vuln === '1')}>脆弱性あり</button>
        <button type="button" onClick={() => setVuln(vuln === 'kev' ? '' : 'kev')} className={chip(vuln === 'kev')}>KEVのみ</button>
        <span className="ml-auto text-xs text-muted">{loading ? '検索中…' : `${data.total} 件`}</span>
      </div>

      <div className="hidden overflow-x-auto rounded border border-line sm:block">
        <table className="tbl text-sm">
          <thead><tr><th>パッケージ</th><th>バージョン</th><th>エコシステム</th><th>ライセンス</th><th>脆弱性</th><th>使用ホスト</th><th>プロジェクト</th></tr></thead>
          <tbody>
            {data.rows.map((d, i) => (
              <tr key={i}>
                <td className="break-all font-mono font-semibold">{d.pkg}</td>
                <td className="whitespace-nowrap font-mono text-xs text-muted tabular-nums">{d.version.slice(0, 40)}</td>
                <td className="whitespace-nowrap text-xs text-muted">{d.eco}</td>
                <td className="whitespace-nowrap"><Lic d={d} /></td>
                <td><Vuln v={d.vuln} /></td>
                <td><Uses d={d} /></td>
                <td><Projects d={d} /></td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <div className="space-y-2 sm:hidden">
        {data.rows.map((d, i) => (
          <div key={i} className="rounded-lg border border-line bg-panel p-3">
            <div className="flex items-baseline justify-between gap-2"><span className="break-all font-mono text-sm font-semibold">{d.pkg}</span><Vuln v={d.vuln} /></div>
            <div className="mt-1 flex flex-wrap items-center gap-x-3 gap-y-1 text-xs text-muted"><span className="font-mono tabular-nums">{d.version.slice(0, 40)}</span><span>{d.eco}</span><Lic d={d} /></div>
            <div className="mt-1 text-xs"><span className="text-muted">ホスト：</span><Uses d={d} /></div>
            <div className="text-xs"><span className="text-muted">プロジェクト：</span><Projects d={d} /></div>
          </div>
        ))}
      </div>

      {data.total === 0 && !loading && <p className="py-6 text-center text-sm text-muted">一致する部品はありません。</p>}
      {pages > 1 && (
        <div className="flex items-center justify-center gap-4 text-sm text-muted">
          <button type="button" className="btn-ghost" disabled={page === 0} onClick={() => setPage((p) => p - 1)}>← 前</button>
          <span>{page + 1} / {pages}</span>
          <button type="button" className="btn-ghost" disabled={page >= pages - 1} onClick={() => setPage((p) => p + 1)}>次 →</button>
        </div>
      )}
    </div>
  );
}
