import Link from 'next/link';
import { GlobalSearch } from '@/components/GlobalSearch';
import { BottomTabs, TopNav } from '@/components/Nav';
import { requireUser } from '@/lib/auth';
import { actionBadge } from '@/lib/tasks';
import { logout } from '../(auth)/actions';

export default async function ConsoleLayout({ children }: { children: React.ReactNode }) {
  const user = await requireUser();
  const badge = await actionBadge();
  return (
    <div className="min-h-screen pb-20 md:pb-0">
      <header className="sticky top-0 z-30 border-b border-line bg-panel">
        <div className="mx-auto flex max-w-7xl items-center gap-3 px-4 py-2.5">
          <Link href="/" className="font-semibold">minisoc2</Link>
          <TopNav badge={badge} />
          <div className="ml-auto w-full max-w-md"><GlobalSearch /></div>
          <details className="group relative">
            <summary className="btn-ghost list-none" aria-label="設定とアカウント">⚙</summary>
            <div className="absolute right-0 z-40 mt-2 w-56 rounded-lg border border-line bg-panel p-2 shadow-lg">
              <Link href="/settings" className="block rounded px-3 py-2 text-sm hover:bg-bg">通知と検知の設定</Link>
              <Link href="/watch" className="block rounded px-3 py-2 text-sm hover:bg-bg">CVE監視</Link>
              <Link href="/enroll" className="block rounded px-3 py-2 text-sm hover:bg-bg">ホスト追加・エージェント</Link>
              <div className="my-1 border-t border-line" />
              <div className="truncate px-3 py-1 text-xs text-muted">{user.email}</div>
              <form action={logout}><button className="block w-full rounded px-3 py-2 text-left text-sm hover:bg-bg">ログアウト</button></form>
            </div>
          </details>
        </div>
      </header>
      <main className="mx-auto max-w-7xl space-y-6 overflow-x-hidden px-4 py-6">{children}</main>
      <BottomTabs badge={badge} />
    </div>
  );
}
