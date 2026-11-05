// Demo masking: deterministic pseudonyms for identity-revealing strings (host names, addresses, system
// names, paths, e-mails, domains) so the dashboard can be screen-shared to outsiders without leaking who
// is being monitored. The SAME input always maps to the SAME pseudonym (via a stable hash of the key),
// so a host reads consistently across every page and chart. Purely presentational — non-identifying data
// (CVE ids, package names, severities, counts, dates) is never masked. Generic / no host-specifics.
export type MaskKind = 'host' | 'addr' | 'system' | 'path' | 'email' | 'domain' | 'generic';

// FNV-1a → 4 base36 chars. Stable across server and client (no crypto needed; this is not a secret).
function shortHash(s: string): string {
  let h = 2166136261 >>> 0;
  for (let i = 0; i < s.length; i++) { h ^= s.charCodeAt(i); h = Math.imul(h, 16777619); }
  return (h >>> 0).toString(36).toUpperCase().slice(0, 4).padStart(4, '0');
}

export function pseudo(kind: MaskKind, key: string): string {
  const h = shortHash(key || '');
  switch (kind) {
    case 'host': return `ホスト-${h}`;
    case 'addr': return `host-${h}.internal`;
    case 'system': return `環境-${h}`;
    case 'email': return `user-${h}@example.com`;
    case 'domain': return `demo-${h}.example`;
    case 'path': return `…/${h}`;
    default: return `＊＊${h}`;
  }
}

export const MASK_COOKIE = 'minisoc2_mask';

// Free-text masking for generated titles / details (detections, audit log, timeline), where an identity
// can appear anywhere in a sentence. Heuristic: pseudonymise anything shaped like an e-mail, an IPv4
// address, an absolute user/data path, or a domain/FQDN. CVE ids, package names and version numbers do
// not match (they have no TLD-like tail), so they are left intact. For a demo, over-masking a stray
// token is safer than leaking one.
const FREE_RE = /(?<email>[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,})|(?<ip>\b\d{1,3}(?:\.\d{1,3}){3}\b)|(?<path>\/(?:home|Users|root|srv|opt|data|mnt|var\/www)\/[^\s'"`)]*)|(?<domain>\b(?:[a-z0-9-]+\.)+[a-z]{2,}\b)/gi;
const FILE_EXT = new Set(['js', 'ts', 'tsx', 'jsx', 'mjs', 'cjs', 'py', 'json', 'lock', 'txt', 'md', 'go', 'rb', 'php', 'yml', 'yaml', 'sh', 'conf', 'cfg', 'ini', 'log', 'html', 'css', 'xml', 'sql', 'gz', 'tar', 'zip', 'rs', 'java', 'c', 'h', 'cpp', 'so', 'service']);

export function maskFree(s: string): string {
  return s.replace(FREE_RE, (m, ...args) => {
    const g = args[args.length - 1] as Record<string, string | undefined>;
    if (g.email) return pseudo('email', g.email);
    if (g.ip) return pseudo('addr', g.ip);
    if (g.path) return pseudo('path', g.path);
    if (g.domain) { const last = g.domain.split('.').pop()!.toLowerCase(); return FILE_EXT.has(last) ? g.domain : pseudo('domain', g.domain); }
    return m;
  });
}
