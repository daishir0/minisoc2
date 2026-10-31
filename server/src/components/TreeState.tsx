'use client';

import { useEffect } from 'react';

// Remembers which host rows on /hosts are expanded, per browser, so the tree reopens as you left it.
// Operates on the server-rendered <details data-host> nodes; localStorage is per-viewer and best-effort.
const KEY = 'minisoc2.hosts.open';

export function TreeState() {
  useEffect(() => {
    let state: Record<string, boolean> = {};
    try { state = JSON.parse(localStorage.getItem(KEY) || '{}'); } catch { /* unavailable/private mode */ }
    const save = (s: Record<string, boolean>) => { try { localStorage.setItem(KEY, JSON.stringify(s)); } catch { /* ignore */ } };
    for (const d of Array.from(document.querySelectorAll<HTMLDetailsElement>('details[data-host]'))) {
      const id = d.getAttribute('data-host');
      if (!id) continue;
      if (id in state) d.open = state[id];
      d.addEventListener('toggle', () => { state[id] = d.open; save(state); });
    }
  }, []);
  return null;
}
