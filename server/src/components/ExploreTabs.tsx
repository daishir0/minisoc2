import { SubTabs } from './SubTabs';
import { navCounts } from '@/lib/navcounts';

// Sub-navigation for the 脅威 section (problems needing attention). 脆弱性 leads because it is the headline,
// most-actionable state (KEV/critical) and must match the section's landing page (/findings) — the leftmost
// tab is always where the top-nav link lands. CVE照会 is now a header tool and SBOM moved to 資産.
export async function ExploreTabs() {
  const c = await navCounts();
  return (
    <SubTabs tabs={[
      { href: '/findings', label: '脆弱性', badge: c.vuln, tone: 'red' },
      { href: '/logs', label: 'ログ', badge: c.logThreat, tone: 'amber' },
      { href: '/alerts', label: 'アラート', badge: c.detectAlerts, tone: 'red' },
      { href: '/changes', label: '変化の履歴' },
      { href: '/integrity', label: 'ファイル改ざん', badge: c.fileChange, tone: 'red' },
    ]} />
  );
}
