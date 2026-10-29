'use client';

import { useRouter } from 'next/navigation';
import { useEffect, useRef, useState } from 'react';

type Item = { type: string; label: string; sub: string; href: string };

// Header search for CVEs, hosts, systems and packages. "/" focuses it on desktop.
export function GlobalSearch({ compact }: { compact?: boolean }) {
  const router = useRouter();
  const [q, setQ] = useState('');
  const [items, setItems] = useState<Item[]>([]);
  const [open, setOpen] = useState(false);
  const [sel, setSel] = useState(0);
  const input = useRef<HTMLInputElement>(null);
  const timer = useRef<ReturnType<typeof setTimeout> | null>(null);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      const t = e.target as HTMLElement;
      if (e.key === '/' && !['INPUT', 'TEXTAREA', 'SELECT'].includes(t.tagName)) {
        e.preventDefault();
        input.current?.focus();
      }
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, []);

  useEffect(() => {
    if (timer.current) clearTimeout(timer.current);
    if (q.trim().length < 2) {
      setItems([]);
      return;
    }
    timer.current = setTimeout(async () => {
      const r = await fetch(`/api/search?q=${encodeURIComponent(q.trim())}`);
      if (r.ok) {
        setItems(await r.json());
        setSel(0);
      }
    }, 180);
  }, [q]);

  const go = (href: string) => {
    setOpen(false);
    setQ('');
    router.push(href);
  };

  return (
    <div className="relative w-full">
      <input
        ref={input}
        value={q}
        onChange={(e) => { setQ(e.target.value); setOpen(true); }}
        onFocus={() => setOpen(true)}
        onBlur={() => setTimeout(() => setOpen(false), 150)}
        onKeyDown={(e) => {
          if (e.key === 'ArrowDown') { e.preventDefault(); setSel((s) => Math.min(s + 1, items.length - 1)); }
          if (e.key === 'ArrowUp') { e.preventDefault(); setSel((s) => Math.max(s - 1, 0)); }
          if (e.key === 'Enter' && items[sel]) { e.preventDefault(); go(items[sel].href); }
          if (e.key === 'Escape') setOpen(false);
        }}
        placeholder={compact ? 'CVE・ホスト・パッケージを検索' : 'CVE・ホスト・システム・パッケージを検索（/）'}
        className="input font-mono text-sm"
        autoCapitalize="none"
        autoCorrect="off"
        spellCheck={false}
        aria-label="検索"
      />
      {open && q.trim().length >= 2 && (
        <div className="absolute left-0 right-0 z-30 mt-1 max-h-96 overflow-y-auto rounded-md border border-line bg-panel shadow-lg">
          {items.length === 0 ? (
            <p className="px-3 py-2 text-sm text-muted">見つかりません。CVE は CVE-2026-12345 の形で入力すると外部の情報も照会できます。</p>
          ) : (
            <ul>
              {items.map((it, i) => (
                <li key={it.type + it.href}>
                  <button type="button" onMouseDown={() => go(it.href)} className={`flex w-full items-center gap-2 px-3 py-2 text-left text-sm ${i === sel ? 'bg-bg' : ''}`}>
                    <span className="w-16 shrink-0 text-[11px] text-muted">{it.type}</span>
                    <span className="min-w-0 truncate font-mono">{it.label}</span>
                    {it.sub && <span className="ml-auto truncate pl-2 text-xs text-muted">{it.sub}</span>}
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
