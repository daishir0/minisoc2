import { SubTabs } from './SubTabs';
import { navCounts } from '@/lib/navcounts';

// Sub-navigation for the 検知 section. Tab order follows real usage (from access-log analysis): the most-
// used tools sit first so they are reachable without scrolling on a phone. CVE照会 is heavily used and was
// moved up from the far end; SBOM (fleet-wide component inventory) replaces the old ライセンス tab.
export async function ExploreTabs() {
  const c = await navCounts();
  return (
    <SubTabs tabs={[
      { href: '/logs', label: 'ログ', badge: c.logThreat, tone: 'amber' },
      { href: '/findings', label: '脆弱性', badge: c.vuln, tone: 'red' },
      { href: '/explore', label: 'CVE照会' },
      { href: '/alerts', label: 'アラート', badge: c.detectAlerts, tone: 'red' },
      { href: '/changes', label: '変化の履歴' },
      { href: '/integrity', label: 'ファイル改ざん', badge: c.fileChange, tone: 'red' },
      { href: '/sbom', label: 'SBOM' },
    ]} />
  );
}
