import { SubTabs } from './SubTabs';

export function AssetTabs() {
  return <SubTabs tabs={[{ href: '/hosts', label: 'ホスト' }, { href: '/systems', label: 'システム' }]} action={{ href: '/enroll', label: '＋ホスト追加' }} />;
}
