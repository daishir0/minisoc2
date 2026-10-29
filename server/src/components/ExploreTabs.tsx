import { SubTabs } from './SubTabs';

export function ExploreTabs() {
  return (
    <SubTabs tabs={[
      { href: '/findings', label: '脆弱性' }, { href: '/logs', label: 'ログ脅威' }, { href: '/integrity', label: 'ファイル改ざん' },
      { href: '/changes', label: '変化の履歴' }, { href: '/explore', label: 'CVE照会' }, { href: '/alerts', label: 'アラート' },
    ]} />
  );
}
