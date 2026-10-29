'use client';

import { useRouter } from 'next/navigation';
import { useEffect, useRef, useState } from 'react';

const WHERE: Record<string, string> = {
  findings: '脆弱性一覧', os_pending: 'OS未適用', os_fixed: 'OS適用済み', kev: 'KEV', watch: '監視中', lookup: '照会済み', osv: 'OSV',
};

// Incremental search over CVEs minisoc2 already knows; Enter looks up any CVE id (also unknown ones).
export function CveSearch({ autoFocus }: { autoFocus?: boolean }) {
  const router = useRouter();
  const [q, setQ] = useState('');
  const [items, setItems] = useState<{ id: string; where: string[] }[]>([]);
  const [busy, setBusy] = useState(false);
  const timer = useRef<ReturnType<typeof setTimeout> | null>(null);

  useEffect(() => {
    if (timer.current) clearTimeout(timer.current);
    const v = q.trim();
    if (v.length < 5) {
      setItems([]);
      return;
    }
    timer.current = setTimeout(async () => {
      const res = await fetch(`/api/cve/search?q=${encodeURIComponent(v)}`);
      if (res.ok) setItems(await res.json());
    }, 200);
  }, [q]);

  const go = (id: string) => {
    setBusy(true);
    router.push(`/cve/${encodeURIComponent(id.trim().toUpperCase())}`);
  };
  const exact = /^CVE-\d{4}-\d{4,}$/i.test(q.trim());

  return (
    <div className="relative">
      <form
        onSubmit={(e) => {
          e.preventDefault();
          if (exact) go(q);
          else if (items[0]) go(items[0].id);
        }}
        className="flex gap-2"
      >
        <input
          value={q}
          onChange={(e) => setQ(e.target.value)}
          placeholder="CVE-2026-109618"
          className="input font-mono"
          autoFocus={autoFocus}
          autoCapitalize="characters"
          autoCorrect="off"
          spellCheck={false}
          inputMode="text"
        />
        <button className="btn whitespace-nowrap" disabled={busy || (!exact && !items.length)}>{busy ? '照会中…' : '照会'}</button>
      </form>
      {q.trim().length >= 5 && (
        <div className="mt-2 rounded-md border border-line bg-panel">
          {items.length === 0 ? (
            <p className="px-3 py-2 text-sm text-muted">
              {exact ? 'minisoc2 の手元のデータにはありません。「照会」を押すと、NVD と GitHub Advisory から最新の情報を取りに行って判定します。' : '一致する CVE はありません。CVE-2026-12345 の形で入力すると、手元に無い CVE も照会できます。'}
            </p>
          ) : (
            <ul className="max-h-80 divide-y divide-line overflow-y-auto">
              {items.map((it) => (
                <li key={it.id}>
                  <button type="button" onClick={() => go(it.id)} className="flex w-full flex-wrap items-center gap-2 px-3 py-2 text-left hover:bg-bg">
                    <span className="font-mono text-sm">{it.id}</span>
                    {it.where.map((w) => <span key={w} className="rounded bg-bg px-1.5 py-0.5 text-[11px] text-muted">{WHERE[w] ?? w}</span>)}
                  </button>
                </li>
              ))}
            </ul>
          )}
        </div>
      )}
    </div>
  );
}
