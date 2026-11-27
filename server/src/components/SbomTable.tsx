'use client';

import { useMemo, useState } from 'react';

// On-screen SBOM component list with incremental search + one-tap filters (ecosystem / has-vuln /
// copyleft). Responsive: a table on desktop, stacked cards on phones. License class is decided server-side
// (classifyLicense imports the DB) and passed in as `cls`.
export interface Comp {
  pkg: string; version: string; eco: string; license: string;
  cls: 'strong' | 'weak' | 'perm' | 'unk'; purl: string; vuln: '' | 'kev' | 'crit';
}

const CLS: Record<Comp['cls'], [string, string]> = {
  strong: ['bg-red-100 text-red-700 dark:bg-red-950 dark:text-red-200', '強'],
  weak: ['bg-amber-100 text-amber-800 dark:bg-amber-950 dark:text-amber-200', '弱'],
  perm: ['bg-green-100 text-green-700 dark:bg-green-950 dark:text-green-200', '寛容'],
  unk: ['bg-bg text-muted', '不明'],
};

function hl(s: string, q: string) {
  if (!q) return s;
  const i = s.toLowerCase().indexOf(q);
  if (i < 0) return s;
  return <>{s.slice(0, i)}<mark className="rounded bg-yellow-200 text-slate-900">{s.slice(i, i + q.length)}</mark>{s.slice(i + q.length)}</>;
}

function Vuln({ v }: { v: Comp['vuln'] }) {
  if (v === 'kev') return <span className="rounded bg-red-600 px-1.5 py-0.5 text-[10px] font-bold text-white">KEV</span>;
  if (v === 'crit') return <span className="rounded bg-red-100 px-1.5 py-0.5 text-[10px] font-bold text-red-700 dark:bg-red-950 dark:text-red-200">緊急</span>;
  return <span className="text-xs text-muted">—</span>;
}
function Lic({ d, q }: { d: Comp; q: string }) {
  const [c, l] = CLS[d.cls];
  return <><span className={`rounded px-1.5 py-0.5 text-[10px] font-bold ${c}`}>{l}</span> <span className="font-mono text-xs">{hl(d.license, q)}</span></>;
}

export function SbomTable({ components }: { components: Comp[] }) {
  const [q, setQ] = useState('');
  const [eco, setEco] = useState('');
  const [vuln, setVuln] = useState(false);
  const [copyleft, setCopyleft] = useState(false);
  const ecos = useMemo(() => [...new Set(components.map((c) => c.eco))].sort(), [components]);

  const ql = q.trim().toLowerCase();
  const rows = components.filter((d) => {
    if (eco && d.eco !== eco) return false;
    if (vuln && !d.vuln) return false;
    if (copyleft && !(d.cls === 'strong' || d.cls === 'weak')) return false;
    if (ql && !(d.pkg.toLowerCase().includes(ql) || d.purl.toLowerCase().includes(ql) || d.license.toLowerCase().includes(ql))) return false;
    return true;
  });

  const chip = (on: boolean) => `rounded-full border px-2.5 py-1 text-xs font-semibold ${on ? 'border-transparent bg-accent text-white dark:text-black' : 'border-line bg-panel text-muted'}`;

  return (
    <div className="space-y-3">
      <input
        value={q} onChange={(e) => setQ(e.target.value)} autoComplete="off"
        placeholder="🔍 パッケージ名 / purl / ライセンスで絞り込み（入力即反映）"
        className="input w-full"
      />
      <div className="flex flex-wrap items-center gap-2">
        <button type="button" onClick={() => setEco('')} className={chip(eco === '')}>全エコシステム</button>
        {ecos.map((e) => <button type="button" key={e} onClick={() => setEco(e)} className={chip(eco === e)}>{e}</button>)}
        <span className="mx-1 text-line">|</span>
        <button type="button" onClick={() => setVuln((v) => !v)} className={chip(vuln)}>脆弱性あり</button>
        <button type="button" onClick={() => setCopyleft((v) => !v)} className={chip(copyleft)}>コピーレフト</button>
        <span className="ml-auto text-xs text-muted">{rows.length} / {components.length} 件</span>
      </div>

      {/* desktop table */}
      <div className="hidden overflow-x-auto rounded border border-line sm:block">
        <table className="tbl text-sm">
          <thead><tr><th>パッケージ</th><th>バージョン</th><th>エコシステム</th><th>ライセンス</th><th>purl</th><th>脆弱性</th></tr></thead>
          <tbody>
            {rows.map((d, i) => (
              <tr key={i}>
                <td className="break-all font-mono font-semibold">{hl(d.pkg, ql)}</td>
                <td className="whitespace-nowrap font-mono text-xs text-muted tabular-nums">{d.version.slice(0, 40)}</td>
                <td className="whitespace-nowrap text-xs text-muted">{d.eco}</td>
                <td className="whitespace-nowrap"><Lic d={d} q={ql} /></td>
                <td className="max-w-[240px] truncate font-mono text-xs text-muted" title={d.purl}>{hl(d.purl, ql)}</td>
                <td><Vuln v={d.vuln} /></td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {/* mobile cards */}
      <div className="space-y-2 sm:hidden">
        {rows.map((d, i) => (
          <div key={i} className="rounded-lg border border-line bg-panel p-3">
            <div className="flex items-baseline justify-between gap-2">
              <span className="break-all font-mono text-sm font-semibold">{hl(d.pkg, ql)}</span>
              <Vuln v={d.vuln} />
            </div>
            <div className="mt-1 flex flex-wrap items-center gap-x-3 gap-y-1 text-xs text-muted">
              <span className="font-mono tabular-nums">{d.version.slice(0, 40)}</span>
              <span>{d.eco}</span>
              <span><Lic d={d} q={ql} /></span>
            </div>
            <div className="mt-1 break-all font-mono text-[11px] text-muted">{hl(d.purl, ql)}</div>
          </div>
        ))}
      </div>

      {rows.length === 0 && <p className="py-6 text-center text-sm text-muted">一致する部品はありません。</p>}
    </div>
  );
}
