// Package URL (purl) for a component, by ecosystem. Shared by the SBOM export and the on-screen
// component list so both name components identically. Returns undefined for ecosystems with no purl type.
export function purl(eco: string, name: string, version: string, osId = ''): string | undefined {
  const v = encodeURIComponent(version);
  if (eco === 'npm') return `pkg:npm/${name.startsWith('@') ? `%40${name.slice(1)}` : name}@${v}`;
  if (eco === 'PyPI') return `pkg:pypi/${name}@${v}`;
  if (eco === 'Packagist') return `pkg:composer/${name}@${v}`;
  if (eco === 'rpm') return `pkg:rpm/${osId || 'linux'}/${name}@${v}`;
  if (/^(Debian|Ubuntu)/.test(eco)) return `pkg:deb/${eco.split(':')[0].toLowerCase()}/${name}@${v}`;
  if (/^Alpine/.test(eco)) return `pkg:apk/alpine/${name}@${v}`;
  return undefined;
}
