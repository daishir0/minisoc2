'use client';

import Link from 'next/link';
import { usePathname } from 'next/navigation';

// Four destinations; everything else lives inside them.
export const SECTIONS = [
  { href: '/', label: 'ホーム', icon: '🏠', match: (p: string) => p === '/' },
  { href: '/actions', label: '対応', icon: '✅', match: (p: string) => p.startsWith('/actions') || p.startsWith('/alerts') },
  { href: '/assets', label: '資産', icon: '🖥', match: (p: string) => /^\/(assets|hosts|systems|enroll)/.test(p) },
  { href: '/explore', label: '調べる', icon: '🔎', match: (p: string) => /^\/(explore|cve|findings|logs|changes)/.test(p) },
];

export function TopNav({ badge }: { badge: number }) {
  const path = usePathname();
  return (
    <nav className="hidden gap-1 text-sm md:flex">
      {SECTIONS.map((s) => (
        <Link key={s.href} href={s.href} className={`rounded-md px-3 py-1.5 ${s.match(path) ? 'bg-bg font-semibold text-fg' : 'text-muted hover:text-fg'}`}>
          {s.label}
          {s.href === '/actions' && badge > 0 && <span className="ml-1 rounded-full bg-red-600 px-1.5 text-[11px] text-white">{badge}</span>}
        </Link>
      ))}
    </nav>
  );
}

export function BottomTabs({ badge }: { badge: number }) {
  const path = usePathname();
  return (
    <nav className="fixed inset-x-0 bottom-0 z-20 grid grid-cols-4 border-t border-line bg-panel pb-[env(safe-area-inset-bottom)] md:hidden">
      {SECTIONS.map((s) => (
        <Link key={s.href} href={s.href} className={`relative flex flex-col items-center py-2 text-[11px] ${s.match(path) ? 'font-semibold text-accent' : 'text-muted'}`}>
          <span className="text-lg leading-none">{s.icon}</span>
          {s.label}
          {s.href === '/actions' && badge > 0 && <span className="absolute right-[28%] top-1 rounded-full bg-red-600 px-1.5 text-[10px] text-white">{badge}</span>}
        </Link>
      ))}
    </nav>
  );
}
