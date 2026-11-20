// Client-side log-filter state shared across the /logs overview (charts, heatmap, rule list) and the raw-log
// viewer. The filter lives in the URL; changing it updates the URL in place (history.replaceState — no
// navigation, so the page never reloads or jumps to the top) and broadcasts an event the raw viewer listens
// for to re-fetch its lines. These functions touch `window`, so only call them from client components.
export const LOG_FIELDS = ['host', 'source', 'cat', 'vhost', 'status', 'q', 'rule', 'day', 'hours'] as const;
export type LogField = (typeof LOG_FIELDS)[number];
export type LogFilter = Partial<Record<LogField, string>>;
export const LOG_EVENT = 'minisoc2:logfilter';

export function readLogFilter(): LogFilter {
  const f: LogFilter = {};
  try { const u = new URLSearchParams(location.search); for (const k of LOG_FIELDS) { const v = u.get(k); if (v) f[k] = v; } } catch { /* ignore */ }
  return f;
}

// Merge `patch` into the current filter (a key with '' / null / undefined is removed), update the URL in
// place (anchored to #raw) and notify the raw viewer. Optionally smooth-scroll the raw section into view.
export function applyLogFilter(patch: LogFilter, opts?: { scroll?: boolean }): void {
  const next = readLogFilter();
  for (const [k, v] of Object.entries(patch)) { if (v == null || v === '') delete next[k as LogField]; else next[k as LogField] = v; }
  try {
    const u = new URLSearchParams();
    for (const k of LOG_FIELDS) if (next[k]) u.set(k, next[k]!);
    const qs = u.toString();
    history.replaceState(null, '', location.pathname + (qs ? '?' + qs : '') + '#raw');
    window.dispatchEvent(new CustomEvent(LOG_EVENT, { detail: next }));
    if (opts?.scroll) document.getElementById('raw')?.scrollIntoView({ behavior: 'smooth', block: 'start' });
  } catch { /* ignore */ }
}
