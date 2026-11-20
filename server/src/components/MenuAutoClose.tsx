'use client';

import { useEffect } from 'react';

// A native <details> menu does not close when you click elsewhere. Close any open details[data-autoclose]
// on an outside click or Escape, so the ⚙ menu behaves like a normal dropdown.
export function MenuAutoClose() {
  useEffect(() => {
    const close = (keep?: Node) => document.querySelectorAll<HTMLDetailsElement>('details[data-autoclose][open]').forEach((d) => { if (!keep || !d.contains(keep)) d.open = false; });
    const onDown = (e: MouseEvent) => close(e.target as Node);
    const onKey = (e: KeyboardEvent) => { if (e.key === 'Escape') close(); };
    document.addEventListener('mousedown', onDown);
    document.addEventListener('keydown', onKey);
    return () => { document.removeEventListener('mousedown', onDown); document.removeEventListener('keydown', onKey); };
  }, []);
  return null;
}
