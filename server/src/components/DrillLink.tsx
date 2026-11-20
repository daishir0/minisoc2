'use client';

import type { ReactNode } from 'react';
import { applyLogFilter, type LogFilter } from '@/lib/logfilter';

// A clickable element on the overview (a bar segment, a heatmap cell, a rule row, a status chip) that sets
// the log filter and shows the matching raw logs in place — no page reload, no scroll-to-top.
export function DrillLink({ patch, className, title, scroll = true, children }: { patch: LogFilter; className?: string; title?: string; scroll?: boolean; children: ReactNode }) {
  return (
    <button type="button" title={title} className={className} onClick={() => applyLogFilter(patch, { scroll })}>
      {children}
    </button>
  );
}
