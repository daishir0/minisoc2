'use client';

import { useEffect, useRef, useState } from 'react';
import { GlobalSearch } from './GlobalSearch';

// The global search is rarely used, so it lives behind a magnifier icon instead of an always-on box. Tap
// to reveal the field (a dropdown panel on mobile, inline-width on desktop); Escape or an outside tap closes.
export function SearchToggle() {
  const [open, setOpen] = useState(false);
  const box = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (!open) return;
    const onDown = (e: MouseEvent) => { if (box.current && !box.current.contains(e.target as Node)) setOpen(false); };
    const onKey = (e: KeyboardEvent) => { if (e.key === 'Escape') setOpen(false); };
    document.addEventListener('mousedown', onDown);
    document.addEventListener('keydown', onKey);
    box.current?.querySelector('input')?.focus();
    return () => { document.removeEventListener('mousedown', onDown); document.removeEventListener('keydown', onKey); };
  }, [open]);
  return (
    <div ref={box} className="relative">
      <button type="button" onClick={() => setOpen((o) => !o)} aria-label="検索" aria-expanded={open} className="btn-ghost text-base">🔍</button>
      {open && (
        <div className="fixed inset-x-3 top-14 z-40 sm:absolute sm:inset-x-auto sm:right-0 sm:top-auto sm:mt-2 sm:w-[min(90vw,24rem)]">
          <GlobalSearch compact />
        </div>
      )}
    </div>
  );
}
