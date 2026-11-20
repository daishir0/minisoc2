import { cookies } from 'next/headers';
import Link from 'next/link';
import { Masked, MaskProvider, MaskToggle } from '@/components/Mask';
import { MobileNav, TopNav } from '@/components/Nav';
import { SearchToggle } from '@/components/SearchToggle';
import { MenuAutoClose } from '@/components/MenuAutoClose';
import { requireUser } from '@/lib/auth';
import { MASK_COOKIE } from '@/lib/mask';
import { navCounts } from '@/lib/navcounts';
import { logout } from '../(auth)/actions';

export default async function ConsoleLayout({ children }: { children: React.ReactNode }) {
  const user = await requireUser();
  const counts = await navCounts();
  const badges = { assets: counts.staleHosts, detect: counts.detectAlerts };
  const maskInitial = (await cookies()).get(MASK_COOKIE)?.value === '1';
  return (
    <MaskProvider initial={maskInitial}>
    <div className="min-h-screen">
      <header className="sticky top-0 z-30 border-b border-line bg-panel">
        <div className="mx-auto flex max-w-7xl items-center gap-3 px-4 py-2.5">
          <Link href="/" className="font-semibold">minisoc2</Link>
          <TopNav badges={badges} />
          <div className="ml-auto flex items-center gap-1">
            <SearchToggle />
            <details data-autoclose className="group relative">
              <summary className="btn-ghost list-none" aria-label="設定とアカウント">⚙</summary>
              <div className="absolute right-0 z-40 mt-2 w-60 rounded-lg border border-line bg-panel p-2 shadow-lg">
                <div className="px-1 pb-2"><MaskToggle /></div>
                <div className="my-1 border-t border-line" />
                <Link href="/settings" className="block rounded px-3 py-2 text-sm hover:bg-bg">通知と検知の設定</Link>
                <Link href="/watch" className="block rounded px-3 py-2 text-sm hover:bg-bg">CVE監視</Link>
                <Link href="/enroll" className="block rounded px-3 py-2 text-sm hover:bg-bg">ホスト追加・エージェント</Link>
                <div className="my-1 border-t border-line" />
                <div className="truncate px-3 py-1 text-xs text-muted"><Masked kind="email">{user.email}</Masked></div>
                <form action={logout}><button className="block w-full rounded px-3 py-2 text-left text-sm hover:bg-bg">ログアウト</button></form>
              </div>
            </details>
          </div>
        </div>
        <MobileNav badges={badges} />
      </header>
      <MenuAutoClose />
      <main className="mx-auto max-w-7xl space-y-6 overflow-x-hidden px-4 py-6">{children}</main>
    </div>
    </MaskProvider>
  );
}
