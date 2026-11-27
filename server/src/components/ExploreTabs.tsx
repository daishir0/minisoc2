import { SubTabs } from './SubTabs';
import { navCounts } from '@/lib/navcounts';

// Sub-navigation for the 脅威 section (problems needing attention), ordered by real access-log usage.
// CVE照会 is now a header tool (reachable anywhere) and SBOM moved to 資産 (it is an inventory), so both
// were removed from here.
export async function ExploreTabs() {
  const c = await navCounts();
  return (
    <SubTabs tabs={[
      { href: '/logs', label: 'ログ', badge: c.logThreat, tone: 'amber' },
      { href: '/findings', label: '脆弱性', badge: c.vuln, tone: 'red' },
      { href: '/alerts', label: 'アラート', badge: c.detectAlerts, tone: 'red' },
      { href: '/changes', label: '変化の履歴' },
      { href: '/integrity', label: 'ファイル改ざん', badge: c.fileChange, tone: 'red' },
    ]} />
  );
}
