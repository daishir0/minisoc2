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
