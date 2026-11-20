'use client';

import Link from 'next/link';
import { usePathname } from 'next/navigation';
import { useEffect, useRef, useState } from 'react';

export interface SubTab { href: string; label: string; badge?: number; tone?: 'red' | 'amber' }

// Horizontal sub-navigation that stays a single compact row on every screen. On touch it scrolls sideways
// only (touch-action: pan-x, so a sideways drag never fights the page's vertical scroll). Edge fades show
// when more tabs are off-screen, and the active tab is scrolled into view on load so it is never hidden.
export function SubTabs({ tabs, action }: { tabs: SubTab[]; action?: { href: string; label: string } }) {
  const path = usePathname();
  const scroller = useRef<HTMLDivElement>(null);
  const activeRef = useRef<HTMLAnchorElement>(null);
  const [edge, setEdge] = useState({ left: false, right: false });

  const updateEdges = () => {
    const el = scroller.current;
    if (!el) return;
    setEdge({ left: el.scrollLeft > 4, right: el.scrollLeft + el.clientWidth < el.scrollWidth - 4 });
  };
  useEffect(() => {
    updateEdges();
    activeRef.current?.scrollIntoView({ inline: 'center', block: 'nearest' });
    const el = scroller.current;
    if (!el) return;
    const ro = new ResizeObserver(updateEdges);
    ro.observe(el);
    return () => ro.disconnect();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [path]);

  return (
    <div className="flex items-stretch gap-2 border-b border-line">
      <div className="relative min-w-0 flex-1">
        {edge.left && <div className="pointer-events-none absolute inset-y-0 left-0 z-10 w-8 bg-gradient-to-r from-panel to-transparent" />}
        {edge.right && <div className="pointer-events-none absolute inset-y-0 right-0 z-10 w-8 bg-gradient-to-l from-panel to-transparent" />}
        <div
          ref={scroller}
          onScroll={updateEdges}
          className="flex items-center gap-1 overflow-x-auto [scrollbar-width:none] [touch-action:pan-x] [overscroll-behavior-x:contain] [-webkit-overflow-scrolling:touch] [&::-webkit-scrollbar]:hidden"
        >
          {tabs.map((t) => {
            const active = path === t.href || path.startsWith(t.href + '/');
            return (
              <Link
                key={t.href}
                ref={active ? activeRef : undefined}
                href={t.href}
                className={`-mb-px flex min-h-[44px] shrink-0 items-center whitespace-nowrap border-b-2 px-3 text-sm ${active ? 'border-accent font-semibold' : 'border-transparent text-muted hover:text-fg'}`}
              >
                {t.label}
                {t.badge ? (
                  <span className={`ml-1 rounded-full px-1.5 text-[10px] leading-4 text-white ${t.tone === 'amber' ? 'bg-amber-500' : 'bg-red-600'}`}>{t.badge}</span>
                ) : null}
              </Link>
            );
          })}
        </div>
      </div>
      {action && <Link href={action.href} className="btn-ghost mb-1 shrink-0 self-center whitespace-nowrap">{action.label}</Link>}
    </div>
  );
}
