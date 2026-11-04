// Pure version helpers (no server-only imports) so both server code and client components can use
// them. Used to turn an advisory's multi-branch "fixed" list into a sensible upgrade target.

// Loose version ordering good enough for semver / PEP 440 / composer style versions.
export function compareVersions(a: string, b: string): number {
  const norm = (v: string) => v.trim().replace(/^v/i, '');
  const [am, ap = ''] = norm(a).split(/-(.*)/s);
  const [bm, bp = ''] = norm(b).split(/-(.*)/s);
  const pa = am.split(/[.+]/);
  const pb = bm.split(/[.+]/);
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    const x = pa[i] ?? '0';
    const y = pb[i] ?? '0';
    const nx = parseInt(x, 10);
    const ny = parseInt(y, 10);
    if (!Number.isNaN(nx) && !Number.isNaN(ny) && nx !== ny) return nx - ny;
    if (Number.isNaN(nx) || Number.isNaN(ny)) {
      const c = x.localeCompare(y);
      if (c) return c;
    }
    const sx = x.replace(/^\d+/, '');
    const sy = y.replace(/^\d+/, '');
    if (sx !== sy) return sx === '' ? 1 : sy === '' ? -1 : sx.localeCompare(sy);
  }
  if (ap === bp) return 0;
  return ap === '' ? 1 : bp === '' ? -1 : ap.localeCompare(bp); // a pre-release sorts before its release
}

const major = (v: string) => v.trim().replace(/^v/i, '').split('.')[0];

// Debian/Ubuntu (dpkg) version comparison. The generic compareVersions() above compares the part after
// the first '-' lexically, which mis-orders kernel ABIs whose digit counts differ (e.g. it ranks
// "6.8.0-1069.74" BELOW "6.8.0-45.45" because '1' < '4'). This implements dpkg's algorithm
// (epoch : upstream - revision, with '~' sorting before everything and digit runs compared numerically)
// so OS/kernel fixed-version checks are correct. Also fine for rpm "6.1.x-y.amzn2023" style strings.
export function compareDebian(a: string, b: string): number {
  const split = (v: string) => {
    v = v.trim();
    let epoch = 0, rest = v;
    const ec = v.indexOf(':');
    if (ec > 0 && /^\d+$/.test(v.slice(0, ec))) { epoch = parseInt(v.slice(0, ec), 10); rest = v.slice(ec + 1); }
    const dash = rest.lastIndexOf('-');
    return { epoch, up: dash >= 0 ? rest.slice(0, dash) : rest, rev: dash >= 0 ? rest.slice(dash + 1) : '0' };
  };
  const cmpNum = (x: string, y: string) => {
    x = x.replace(/^0+/, '') || '0'; y = y.replace(/^0+/, '') || '0';
    return x.length !== y.length ? (x.length < y.length ? -1 : 1) : (x < y ? -1 : x > y ? 1 : 0);
  };
  const ord = (c: string) => (c === '~' ? -1 : c === '' ? 0 : /[A-Za-z]/.test(c) ? c.charCodeAt(0) : c.charCodeAt(0) + 256);
  const cmpPart = (x: string, y: string): number => {
    let i = 0, j = 0;
    while (i < x.length || j < y.length) {
      while ((i < x.length && !/[0-9]/.test(x[i])) || (j < y.length && !/[0-9]/.test(y[j]))) {
        const cx = i < x.length && !/[0-9]/.test(x[i]) ? x[i] : '';
        const cy = j < y.length && !/[0-9]/.test(y[j]) ? y[j] : '';
        const d = ord(cx) - ord(cy);
        if (d) return d < 0 ? -1 : 1;
        if (cx) i++;
        if (cy) j++;
      }
      let dx = '', dy = '';
      while (i < x.length && /[0-9]/.test(x[i])) dx += x[i++];
      while (j < y.length && /[0-9]/.test(y[j])) dy += y[j++];
      const d = cmpNum(dx, dy);
      if (d) return d;
    }
    return 0;
  };
  const A = split(a), B = split(b);
  if (A.epoch !== B.epoch) return A.epoch < B.epoch ? -1 : 1;
  return cmpPart(A.up, B.up) || cmpPart(A.rev, B.rev);
}

// For ONE advisory (which may list fixes across several release branches), the version to recommend:
// the smallest fix on the installed version's own major that is newer than what is installed. This
// avoids telling a 16.x app to "fix" by moving to a 15.x patch. Falls back to the smallest forward
// fix on any branch, then to the highest fix listed.
export function bestFixTarget(current: string, fixed: string[]): string {
  const cur = splitVers(current).sort(compareVersions).pop() || '';
  const fx = [...new Set(fixed.flatMap((f) => splitVers(f)))];
  if (!fx.length) return '';
  if (!cur) return fx.slice().sort(compareVersions).pop() || '';
  const ahead = fx.filter((f) => compareVersions(f, cur) > 0);
  const sameMajor = ahead.filter((f) => major(f) === major(cur)).sort(compareVersions);
  if (sameMajor.length) return sameMajor[0];
  const anyAhead = ahead.slice().sort(compareVersions);
  if (anyAhead.length) return anyAhead[0];
  return fx.slice().sort(compareVersions).pop() || '';
}

// Across SEVERAL findings on the same package, the single target that clears them all: the highest of
// each finding's own branch-aware fix (so one upgrade covers every selected CVE).
export function recommendedTarget(current: string, perFindingFixed: string[]): string {
  let best = '';
  for (const f of perFindingFixed) {
    const t = bestFixTarget(current, splitVers(f));
    if (t && (!best || compareVersions(t, best) > 0)) best = t;
  }
  return best;
}

function splitVers(s: string): string[] {
  return (s || '').split(',').map((x) => x.trim()).filter(Boolean);
}
