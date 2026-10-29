// Allowed-source-IP checks. An agent (push) or SSH puller reaches the API through the reverse
// proxy, so the client address comes from X-Forwarded-For (see clientIp in body.ts). A host, or the
// global default, may restrict which addresses are accepted. An empty list means "no restriction".
//
// Entries are IPv4/IPv6 addresses or CIDR ranges: "203.0.113.4", "203.0.113.0/24", "2001:db8::/32".

function ipv4ToInt(ip: string): number | null {
  const m = ip.trim().match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (!m) return null;
  let n = 0;
  for (let i = 1; i <= 4; i++) {
    const o = Number(m[i]);
    if (o > 255) return null;
    n = (n * 256 + o) >>> 0;
  }
  return n >>> 0;
}

// Expand an IPv6 (incl. "::" and embedded IPv4) to a 128-bit BigInt, or null if malformed.
function ipv6ToBig(ip: string): bigint | null {
  let s = ip.trim().toLowerCase();
  if (s.startsWith('[') && s.endsWith(']')) s = s.slice(1, -1);
  s = s.replace(/%.*$/, ''); // drop zone id
  if (!s.includes(':')) return null;
  // embedded IPv4 (::ffff:1.2.3.4)
  const v4 = s.match(/(\d{1,3}(?:\.\d{1,3}){3})$/);
  if (v4) {
    const n = ipv4ToInt(v4[1]);
    if (n == null) return null;
    s = s.slice(0, v4.index) + `${(n >>> 16).toString(16)}:${(n & 0xffff).toString(16)}`;
  }
  const halves = s.split('::');
  if (halves.length > 2) return null;
  const head = halves[0] ? halves[0].split(':') : [];
  const tail = halves.length === 2 ? (halves[1] ? halves[1].split(':') : []) : [];
  const missing = 8 - head.length - tail.length;
  if (halves.length === 1 ? head.length !== 8 : missing < 0) return null;
  const groups = halves.length === 2 ? [...head, ...Array(missing).fill('0'), ...tail] : head;
  let out = 0n;
  for (const g of groups) {
    if (!/^[0-9a-f]{1,4}$/.test(g)) return null;
    out = (out << 16n) + BigInt(parseInt(g, 16));
  }
  return out;
}

// Does `ip` fall within the single rule `entry` (address or CIDR)?
function matchOne(ip: string, entry: string): boolean {
  const e = entry.trim();
  if (!e) return false;
  const [net, bitsStr] = e.split('/');
  const v4 = ipv4ToInt(ip);
  const netV4 = ipv4ToInt(net);
  if (v4 != null && netV4 != null) {
    const bits = bitsStr === undefined ? 32 : Number(bitsStr);
    if (!(bits >= 0 && bits <= 32)) return false;
    if (bits === 0) return true;
    const mask = bits === 32 ? 0xffffffff : (~((1 << (32 - bits)) - 1)) >>> 0;
    return ((v4 & mask) >>> 0) === ((netV4 & mask) >>> 0);
  }
  const v6 = ipv6ToBig(ip);
  const netV6 = ipv6ToBig(net);
  if (v6 != null && netV6 != null) {
    const bits = bitsStr === undefined ? 128 : Number(bitsStr);
    if (!(bits >= 0 && bits <= 128)) return false;
    if (bits === 0) return true;
    const mask = ((1n << 128n) - 1n) ^ ((1n << BigInt(128 - bits)) - 1n);
    return (v6 & mask) === (netV6 & mask);
  }
  return false;
}

// True when `ip` is permitted. An empty/omitted allow list permits everything.
export function ipAllowed(ip: string, allow: string[] | null | undefined): boolean {
  const list = (allow ?? []).filter(Boolean);
  if (!list.length) return true;
  if (!ip || ip === 'unknown') return false; // a restriction is set but we cannot tell the source
  return list.some((entry) => matchOne(ip, entry));
}

// Validate and normalise user-entered entries; returns the kept entries and any rejected ones.
export function parseAllowList(text: string): { ok: string[]; bad: string[] } {
  const ok: string[] = [];
  const bad: string[] = [];
  for (const line of text.split(/[\n,]/).map((s) => s.trim()).filter(Boolean)) {
    // valid if it matches itself (a well-formed address/CIDR always contains its own network base)
    const base = line.split('/')[0];
    if (ipv4ToInt(base) != null || ipv6ToBig(base) != null) {
      const bitsStr = line.split('/')[1];
      const max = ipv4ToInt(base) != null ? 32 : 128;
      const bits = bitsStr === undefined ? max : Number(bitsStr);
      if (Number.isInteger(bits) && bits >= 0 && bits <= max) {
        ok.push(line);
        continue;
      }
    }
    bad.push(line);
  }
  return { ok: [...new Set(ok)], bad };
}
