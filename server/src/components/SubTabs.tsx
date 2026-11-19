'use client';

import Link from 'next/link';
import { usePathname } from 'next/navigation';

export interface SubTab { href: string; label: string; badge?: number; tone?: 'red' | 'amber' }

// Horizontal sub-navigation. On narrow screens the tab row scrolls sideways (instead of being clipped
// off-screen, which happened before), so every tab stays reachable with a swipe. An optional action
// button sits outside the scroll area so it is always visible.
export function SubTabs({ tabs, action }: { tabs: SubTab[]; action?: { href: string; label: string } }) {
  const path = usePathname();
  return (
    <div className="flex items-stretch gap-2 border-b border-line">
      <div className="flex min-w-0 flex-1 items-center gap-1 overflow-x-auto [scrollbar-width:none] [-webkit-overflow-scrolling:touch] [&::-webkit-scrollbar]:hidden">
        {tabs.map((t) => {
          const active = path === t.href || path.startsWith(t.href + '/');
          return (
            <Link
              key={t.href}
              href={t.href}
              className={`-mb-px flex shrink-0 items-center whitespace-nowrap border-b-2 px-3 py-2 text-sm ${active ? 'border-accent font-semibold' : 'border-transparent text-muted hover:text-fg'}`}
            >
              {t.label}
              {t.badge ? (
                <span className={`ml-1 rounded-full px-1.5 text-[10px] leading-4 text-white ${t.tone === 'amber' ? 'bg-amber-500' : 'bg-red-600'}`}>{t.badge}</span>
              ) : null}
            </Link>
          );
        })}
      </div>
      {action && <Link href={action.href} className="btn-ghost mb-1 shrink-0 self-center whitespace-nowrap">{action.label}</Link>}
    </div>
  );
}
