import { SubTabs } from './SubTabs';

// Sub-navigation for the 資産 section: the things being monitored. ホスト (and their projects) and the
// fleet-wide SBOM component inventory — SBOM is an inventory of assets, so it lives here, not under 脅威.
export function AssetTabs() {
  return (
    <SubTabs tabs={[
      { href: '/hosts', label: 'ホスト' },
      { href: '/sbom', label: 'SBOM' },
    ]} />
  );
}
