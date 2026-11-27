import { SubTabs } from './SubTabs';
import { navCounts } from '@/lib/navcounts';

// Sub-navigation for the 検知 section. Primary tabs (what usually needs action) come first so they fit a
// phone before scrolling; 変化の履歴 and CVE照会 are reference tools and sit at the end. Badges show the
// current open counts per tab.
export async function ExploreTabs() {
  const c = await navCounts();
  return (
    <SubTabs tabs={[
      { href: '/findings', label: '脆弱性', badge: c.vuln, tone: 'red' },
      { href: '/logs', label: 'ログ', badge: c.logThreat, tone: 'amber' },
      { href: '/integrity', label: 'ファイル改ざん', badge: c.fileChange, tone: 'red' },
      { href: '/alerts', label: 'アラート', badge: c.detectAlerts, tone: 'red' },
      { href: '/licenses', label: 'ライセンス' },
      { href: '/changes', label: '変化の履歴' },
      { href: '/explore', label: 'CVE照会' },
    ]} />
  );
}
