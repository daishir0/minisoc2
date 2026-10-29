import Link from 'next/link';

// Clickable breadcrumb trail. The last item is the current page (no link).
export function Breadcrumbs({ items }: { items: { label: string; href?: string }[] }) {
  return (
    <nav aria-label="パンくず" className="flex flex-wrap items-center gap-1 text-xs text-muted">
      {items.map((it, i) => (
        <span key={i} className="flex items-center gap-1">
          {it.href ? <Link href={it.href} className="hover:text-accent hover:underline">{it.label}</Link> : <span className="text-fg">{it.label}</span>}
          {i < items.length - 1 && <span aria-hidden="true" className="opacity-50">›</span>}
        </span>
      ))}
    </nav>
  );
}

// Common prefixes so pages stay consistent.
export const CRUMB = {
  home: { label: 'ホーム', href: '/' },
  assets: { label: '資産', href: '/hosts' },
  hosts: { label: 'ホスト', href: '/hosts' },
  projects: { label: 'プロジェクト', href: '/hosts' },
  detect: { label: '検知', href: '/findings' },
  findings: { label: '脆弱性', href: '/findings' },
  logs: { label: 'ログ脅威', href: '/logs' },
  integrity: { label: 'ファイル改ざん', href: '/integrity' },
  changes: { label: '変化の履歴', href: '/changes' },
  cveLookup: { label: 'CVE照会', href: '/explore' },
  alerts: { label: 'アラート', href: '/alerts' },
  actions: { label: '対応', href: '/actions' },
  settings: { label: '設定', href: '/settings' },
  watch: { label: 'CVE監視', href: '/watch' },
  enroll: { label: 'ホスト追加', href: '/enroll' },
} as const;
