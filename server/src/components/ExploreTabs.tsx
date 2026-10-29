import { SubTabs } from './SubTabs';

export function ExploreTabs() {
  return (
    <SubTabs tabs={[
      { href: '/explore', label: 'CVE照会' }, { href: '/findings', label: '脆弱性' }, { href: '/changes', label: '変化の履歴' },
      { href: '/logs', label: 'ログ' }, { href: '/alerts', label: '検知の記録' },
    ]} />
  );
}
