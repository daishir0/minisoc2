'use client';

import Link from 'next/link';
import { usePathname } from 'next/navigation';

// Four destinations mapped to the workflow: register assets -> auto-detect (vuln/log/integrity)
// -> remediate. Everything else lives inside them.
// Remediation task pages (/actions/[key]) are reached contextually from the home worklist, host and
// system pages — they no longer have their own top-level tab, so they highlight under 資産.
export const SECTIONS = [
  { href: '/', label: 'ホーム', icon: '🏠', match: (p: string) => p === '/' },
  { href: '/hosts', label: '資産', icon: '🖥', match: (p: string) => /^\/(assets|hosts|systems|enroll|actions)/.test(p) },
  { href: '/findings', label: '検知', icon: '🛡', match: (p: string) => /^\/(detect|findings|logs|integrity|changes|explore|cve|alerts|watch)/.test(p) },
];

export interface NavBadges { assets?: number; detect?: number }
// A section's badge: 資産 = hosts that stopped reporting (amber), 検知 = open important alerts (red).
function badgeFor(href: string, b: NavBadges): { n: number; tone: string } | null {
  if (href === '/hosts' && b.assets) return { n: b.assets, tone: 'bg-amber-500' };
  if (href === '/findings' && b.detect) return { n: b.detect, tone: 'bg-red-600' };
  return null;
}

export function TopNav({ badges = {} }: { badges?: NavBadges }) {
  const path = usePathname();
  return (
    <nav className="hidden gap-1 text-sm md:flex">
      {SECTIONS.map((s) => {
        const b = badgeFor(s.href, badges);
        return (
          <Link key={s.href} href={s.href} className={`rounded-md px-3 py-1.5 ${s.match(path) ? 'bg-bg font-semibold text-fg' : 'text-muted hover:text-fg'}`}>
            {s.label}
            {b && <span className={`ml-1 rounded-full px-1.5 text-[11px] text-white ${b.tone}`}>{b.n}</span>}
          </Link>
        );
      })}
    </nav>
  );
}

export function BottomTabs({ badges = {} }: { badges?: NavBadges }) {
  const path = usePathname();
  return (
    <nav className="fixed inset-x-0 bottom-0 z-20 grid grid-cols-3 border-t border-line bg-panel pb-[env(safe-area-inset-bottom)] md:hidden">
      {SECTIONS.map((s) => {
        const b = badgeFor(s.href, badges);
        return (
          <Link key={s.href} href={s.href} className={`relative flex flex-col items-center py-2 text-[11px] ${s.match(path) ? 'font-semibold text-accent' : 'text-muted'}`}>
            <span className="text-lg leading-none">{s.icon}</span>
            {s.label}
            {b && <span className={`absolute right-[26%] top-1 rounded-full px-1.5 text-[10px] text-white ${b.tone}`}>{b.n}</span>}
          </Link>
        );
      })}
    </nav>
  );
}
