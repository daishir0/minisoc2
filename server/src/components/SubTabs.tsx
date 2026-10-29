'use client';

import Link from 'next/link';
import { usePathname } from 'next/navigation';

export function SubTabs({ tabs, action }: { tabs: { href: string; label: string }[]; action?: { href: string; label: string } }) {
  const path = usePathname();
  return (
    <div className="flex items-center gap-1 border-b border-line">
      {tabs.map((t) => {
        const active = path === t.href || path.startsWith(t.href + '/');
        return (
          <Link key={t.href} href={t.href} className={`-mb-px border-b-2 px-3 py-2 text-sm ${active ? 'border-accent font-semibold' : 'border-transparent text-muted hover:text-fg'}`}>{t.label}</Link>
        );
      })}
      {action && <Link href={action.href} className="btn-ghost mb-1 ml-auto">{action.label}</Link>}
    </div>
  );
}
