'use client';

import { useEffect, useRef, useState } from 'react';
import { CveSearch } from './CveSearch';

// Header CVE照会: a heavily-used tool (access-log analysis) now reachable from anywhere. Tap to reveal the
// incremental CVE lookup; Enter on a CVE id opens its verdict page (even for ids not yet known locally).
export function CveSearchToggle() {
  const [open, setOpen] = useState(false);
  const box = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (!open) return;
    const onDown = (e: MouseEvent) => { if (box.current && !box.current.contains(e.target as Node)) setOpen(false); };
    const onKey = (e: KeyboardEvent) => { if (e.key === 'Escape') setOpen(false); };
    document.addEventListener('mousedown', onDown);
    document.addEventListener('keydown', onKey);
    return () => { document.removeEventListener('mousedown', onDown); document.removeEventListener('keydown', onKey); };
  }, [open]);
  return (
    <div ref={box} className="relative">
      <button type="button" onClick={() => setOpen((o) => !o)} aria-label="CVE照会" aria-expanded={open} className="btn-ghost whitespace-nowrap text-sm">CVE照会</button>
      {open && (
        <div className="absolute right-0 z-40 mt-2 w-[min(90vw,26rem)] rounded-lg border border-line bg-panel p-2 shadow-lg">
          <CveSearch autoFocus />
        </div>
      )}
    </div>
  );
}
