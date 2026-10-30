// "Does this CVE affect us?" — one CVE, a verdict per host, and the evidence behind it.
//   affected     : pending OS security update, open finding, or an installed package inside the vulnerable range
//   fixed        : the OS reports the fixing advisory as installed, or the installed version is outside the range
//   not_present  : the advisory lists its packages and none of them is installed on the host
//   vex          : someone marked it "not affected" with a justification
//   unknown      : no data source says anything about this CVE for the host (shown honestly, never as safe)
import { q, q1 } from './db';
import { classifyComponent, fetchUbuntuCve, ubuntuVerdict, UBUNTU_CODENAME, type UbuntuCve } from './distro';

//   potential : no advisory maps it yet, but the CVE's component is plainly in use (e.g. a kernel CVE
//               on a host running that kernel) — flagged for review, auto-upgrades to affected when a
//               distro advisory lands.
export type HostState = 'affected' | 'fixed' | 'not_present' | 'vex' | 'unknown' | 'potential';

export interface External {
  fetchedAt: string;
  nvd: { description: string; score: number | null; severity: string | null; published: string | null; status: string | null; products: string[] } | null;
  ghsa: { id: string; summary: string; severity: string; packages: { ecosystem: string; name: string; range: string; patched: string | null }[] }[];
  distro?: { ubuntu: UbuntuCve | null } | null;
  errors: string[];
}

export interface HostVerdict {
  hostId: string;
  host: string;
  os: string;
  state: HostState;
  reasons: string[];
}

export interface Verdict {
  cve: string;
  overall: 'affected' | 'clear' | 'unknown';
  hosts: HostVerdict[];
  external: External;
  kev: { name: string; date_added: string } | null;
  watched: boolean;
}

const GHSA_ECO: Record<string, string> = {
  npm: 'npm', pip: 'PyPI', composer: 'Packagist', rubygems: 'RubyGems', maven: 'Maven', nuget: 'NuGet', go: 'Go', rust: 'crates.io',
};

export function normalizeCve(input: string): string | null {
  const m = input.trim().toUpperCase().match(/^CVE-(\d{4})-(\d{4,})$/);
  return m ? `CVE-${m[1]}-${m[2]}` : null;
}

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
    // "1.0rc1" style suffixes
    const sx = x.replace(/^\d+/, '');
    const sy = y.replace(/^\d+/, '');
    if (sx !== sy) return sx === '' ? 1 : sy === '' ? -1 : sx.localeCompare(sy);
  }
  if (ap === bp) return 0;
  return ap === '' ? 1 : bp === '' ? -1 : ap.localeCompare(bp); // a pre-release sorts before its release
}

// GHSA ranges look like ">= 1.0.0, < 1.2.6" or "< 0.2.4" or "= 2.0.0".
export function inRange(version: string, range: string): boolean | null {
  const parts = range.split(',').map((p) => p.trim()).filter(Boolean);
  if (!parts.length) return null;
  for (const p of parts) {
    const m = p.match(/^(>=|<=|>|<|=)\s*(.+)$/);
    if (!m) return null;
    const c = compareVersions(version, m[2]);
    const ok = m[1] === '>=' ? c >= 0 : m[1] === '<=' ? c <= 0 : m[1] === '>' ? c > 0 : m[1] === '<' ? c < 0 : c === 0;
    if (!ok) return false;
  }
  return true;
}

async function fetchJson(url: string, headers: Record<string, string> = {}): Promise<{ status: number; body: unknown }> {
  const ac = new AbortController();
  const t = setTimeout(() => ac.abort(), 10_000);
  try {
    const res = await fetch(url, { headers: { 'user-agent': 'minisoc2', ...headers }, signal: ac.signal });
    return { status: res.status, body: res.ok ? await res.json() : null };
  } finally {
    clearTimeout(t);
  }
}

export async function fetchExternal(cve: string): Promise<External> {
  const ext: External = { fetchedAt: new Date().toISOString(), nvd: null, ghsa: [], distro: { ubuntu: null }, errors: [] };
  const [nvd, gh, ubuntu] = await Promise.allSettled([
    fetchJson(`https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=${cve}`, process.env.NVD_API_KEY ? { apiKey: process.env.NVD_API_KEY } : {}),
    fetchJson(`https://api.github.com/advisories?cve_id=${cve}&per_page=20`, process.env.GITHUB_TOKEN ? { authorization: `Bearer ${process.env.GITHUB_TOKEN}` } : {}),
    fetchUbuntuCve(cve),
  ]);
  if (ubuntu.status === 'fulfilled') ext.distro = { ubuntu: ubuntu.value };
  else ext.errors.push(`Ubuntu Security: ${String(ubuntu.reason)}`);
  if (nvd.status === 'fulfilled' && nvd.value.status === 200) {
    type NvdCve = {
      descriptions?: { lang: string; value: string }[]; published?: string; vulnStatus?: string;
      metrics?: Record<string, { cvssData: { baseScore: number; baseSeverity?: string }; baseSeverity?: string }[]>;
      configurations?: { nodes: { cpeMatch: { criteria: string }[] }[] }[];
    };
    const c = (nvd.value.body as { vulnerabilities?: { cve: NvdCve }[] }).vulnerabilities?.[0]?.cve;
    if (c) {
      const metric = c.metrics?.cvssMetricV40?.[0] ?? c.metrics?.cvssMetricV31?.[0] ?? c.metrics?.cvssMetricV30?.[0];
      const products = new Set<string>();
      for (const cfg of c.configurations ?? []) for (const n of cfg.nodes) for (const m of n.cpeMatch) {
        const f = m.criteria.split(':');
        if (f[3] && f[4]) products.add(`${f[3]} ${f[4]}`);
      }
      ext.nvd = {
        description: c.descriptions?.find((d) => d.lang === 'en')?.value ?? '',
        score: metric?.cvssData.baseScore ?? null,
        severity: (metric?.cvssData.baseSeverity ?? metric?.baseSeverity ?? null)?.toLowerCase() ?? null,
        published: c.published ?? null,
        status: c.vulnStatus ?? null,
        products: [...products].slice(0, 20),
      };
    }
  } else {
    ext.errors.push(`NVD: ${nvd.status === 'fulfilled' ? `HTTP ${nvd.value.status}` : String(nvd.reason)}`);
  }
  if (gh.status === 'fulfilled' && gh.value.status === 200) {
    type Gh = { ghsa_id: string; summary: string; severity: string; vulnerabilities: { package: { ecosystem: string; name: string }; vulnerable_version_range: string; first_patched_version: string | null }[] };
    ext.ghsa = ((gh.value.body as Gh[]) ?? []).map((a) => ({
      id: a.ghsa_id,
      summary: a.summary,
      severity: a.severity,
      packages: (a.vulnerabilities ?? []).map((v) => ({
        ecosystem: GHSA_ECO[v.package.ecosystem] ?? v.package.ecosystem,
        name: v.package.name,
        range: v.vulnerable_version_range ?? '',
        patched: v.first_patched_version ?? null,
      })),
    }));
  } else {
    ext.errors.push(`GitHub Advisory: ${gh.status === 'fulfilled' ? `HTTP ${gh.value.status}` : String(gh.reason)}`);
  }
  return ext;
}

const CACHE_HOURS = 6;

export async function getExternal(cve: string, refresh: boolean): Promise<External> {
  if (!refresh) {
    const c = await q1<{ data: External; fetched_at: Date }>('SELECT data, fetched_at FROM cve_lookups WHERE cve=$1', [cve]);
    if (c && Date.now() - new Date(c.fetched_at).getTime() < CACHE_HOURS * 3600_000 && !c.data.errors?.length) return c.data;
  }
  const ext = await fetchExternal(cve);
  await q(
    `INSERT INTO cve_lookups(cve, data, fetched_at) VALUES ($1,$2, now())
     ON CONFLICT (cve) DO UPDATE SET data=EXCLUDED.data, fetched_at=now()`,
    [cve, JSON.stringify(ext)],
  );
  return ext;
}

export async function lookupCve(cve: string, refresh = false): Promise<Verdict> {
  const external = await getExternal(cve, refresh);
  const hosts = await q<{ id: string; name: string; os_name: string; os_version: string; os_id: string; has_fixed: boolean; has_adv: boolean }>(
    `SELECT id, name, os_name, os_version, os_id,
       EXISTS (SELECT 1 FROM host_fixed_cves x WHERE x.host_id=h.id) AS has_fixed,
       EXISTS (SELECT 1 FROM reports r WHERE r.host_id=h.id AND r.advisory_count IS NOT NULL) AS has_adv
     FROM hosts h WHERE NOT disabled ORDER BY name`,
  );
  const pending = await q<{ host_id: string; pkg: string; fixed: string; advisory: string | null }>('SELECT host_id, pkg, fixed, advisory FROM host_os_advisories WHERE vuln_id=$1', [cve]);
  const fixedRows = await q<{ host_id: string; pkg: string; fixed: string }>('SELECT host_id, pkg, fixed FROM host_fixed_cves WHERE vuln_id=$1', [cve]);
  const findings = await q<{ host_id: string; pkg: string; version: string; fixed: string; status: string; suppress_reason: string | null; systems: string[]; source: string }>(
    `SELECT host_id, pkg, version, fixed, status, suppress_reason, systems, source FROM findings
     WHERE vuln_id=$1 OR vuln_id IN (SELECT id FROM vulns WHERE $1 = ANY(aliases))`,
    [cve],
  );
  const ghsaPkgs = external.ghsa.flatMap((a) => a.packages);
  const installed = ghsaPkgs.length
    ? await q<{ host_id: string; ecosystem: string; name: string; version: string; systems: string[] }>(
        `SELECT p.host_id, p.ecosystem, p.name, p.version,
           ARRAY(SELECT s.name FROM systems s WHERE s.host_id=p.host_id AND s.root = ANY(p.systems) AND NOT s.ignored) AS systems
         FROM host_packages p
         WHERE (p.ecosystem, p.name) IN (SELECT * FROM unnest($1::text[], $2::text[]))
           -- packages that only live in systems marked "ignored" do not count
           AND (cardinality(p.systems) = 0 OR EXISTS (SELECT 1 FROM systems s WHERE s.host_id=p.host_id AND s.root = ANY(p.systems) AND NOT s.ignored))`,
        [ghsaPkgs.map((p) => p.ecosystem), ghsaPkgs.map((p) => p.name)],
      )
    : [];
  const kev = await q1<{ name: string; date_added: string }>("SELECT name, to_char(date_added, 'YYYY-MM-DD') AS date_added FROM kev WHERE cve=$1", [cve]);
  const watched = !!(await q1('SELECT 1 FROM watch_cves WHERE cve=$1', [cve]));

  // Distro advisory (Ubuntu): maps the CVE to OS/kernel packages per release, long before NVD.
  const ub = external.distro?.ubuntu ?? null;
  const ubReasons = new Map<string, { red: string[]; green: string[]; matched: boolean }>();
  const ubHosts = hosts.filter((h) => h.os_id === 'ubuntu');
  if (ub && ub.pkgs.length && ubHosts.length) {
    const names = [...new Set(ub.pkgs.map((p) => p.name))];
    const rows = await q<{ host_id: string; name: string; version: string }>(
      `SELECT host_id, name, version FROM host_packages WHERE host_id = ANY($1) AND ecosystem LIKE 'Ubuntu:%' AND (name = ANY($2) OR name LIKE 'linux-%')`,
      [ubHosts.map((h) => h.id), names]);
    const byHost = new Map<string, { name: string; version: string }[]>();
    for (const r of rows) byHost.set(r.host_id, [...(byHost.get(r.host_id) ?? []), { name: r.name, version: r.version }]);
    for (const h of ubHosts) {
      const codename = UBUNTU_CODENAME[h.os_version] ?? '';
      if (codename) ubReasons.set(h.id, ubuntuVerdict(codename, byHost.get(h.id) ?? [], ub));
    }
  }
  // provisional triage (source C): hosts running a kernel, for a kernel CVE with no mapping yet
  const kernelHosts = classifyComponent(external.nvd?.description ?? '') === 'kernel'
    ? new Set((await q<{ host_id: string }>("SELECT DISTINCT host_id FROM host_packages WHERE name LIKE 'linux-image%' OR name ~ '^kernel($|-)'")).map((r) => r.host_id))
    : new Set<string>();

  const verdicts: HostVerdict[] = hosts.map((h) => {
    const red: string[] = [];
    const green: string[] = [];
    const vex: string[] = [];
    for (const p of pending.filter((x) => x.host_id === h.id)) red.push(`OSの更新が未適用：${p.pkg}（修正版 ${p.fixed}${p.advisory ? ` / ${p.advisory}` : ''}）`);
    const reported = new Set<string>();
    for (const f of findings.filter((x) => x.host_id === h.id)) {
      if (f.status === 'open' && f.source !== 'os-advisory') reported.add(f.pkg);
      if (f.status === 'suppressed') vex.push(`${f.pkg}：影響なしと判断済み（${f.suppress_reason}）`);
    }
    const fixedHere = fixedRows.filter((x) => x.host_id === h.id);
    if (fixedHere.length) {
      const pkgs = [...new Set(fixedHere.map((x) => `${x.pkg} ${x.fixed}`))];
      green.push(`OSの修正を適用済み：${pkgs.slice(0, 4).join('、')}${pkgs.length > 4 ? ` 他${pkgs.length - 4}件` : ''}`);
    }
    let anyGhsaPresent = false;
    const outside = new Map<string, string[]>();
    for (const gp of ghsaPkgs) {
      for (const ip of installed.filter((x) => x.host_id === h.id && x.ecosystem === gp.ecosystem && x.name === gp.name)) {
        anyGhsaPresent = true;
        const r = inRange(ip.version, gp.range);
        const where = ip.systems.length ? `［${ip.systems.slice(0, 3).join('、')}${ip.systems.length > 3 ? ` 他${ip.systems.length - 3}` : ''}］` : '';
        if (r === true) red.push(`${gp.ecosystem} ${gp.name} ${ip.version}${where} が対象範囲（${gp.range}）${gp.patched ? `／修正版 ${gp.patched}` : ''}`);
        else if (r === false) outside.set(`${gp.ecosystem} ${gp.name} ${ip.version}${where}`, [...(outside.get(`${gp.ecosystem} ${gp.name} ${ip.version}${where}`) ?? []), gp.range]);
      }
    }
    for (const [pkg, ranges] of outside) green.push(`${pkg} は対象範囲（${ranges.join(' / ')}）の外`);
    for (const f of findings.filter((x) => x.host_id === h.id && x.status === 'open' && x.source !== 'os-advisory')) {
      if (!red.some((r) => r.includes(` ${f.pkg} `))) red.push(`${f.pkg} ${f.version.slice(0, 60)} が該当${f.fixed ? `（修正版 ${f.fixed}）` : ''}`);
    }
    void reported;
    // distro (Ubuntu) advisory evidence
    const uv = ubReasons.get(h.id);
    let distroMatched = false;
    if (uv) { red.push(...uv.red); green.push(...uv.green); distroMatched = uv.matched; }
    const reasons: string[] = [];
    let state: HostState;
    if (red.length) {
      state = 'affected';
      reasons.push(...[...new Set(red)]);
    } else if (vex.length) {
      state = 'vex';
      reasons.push(...vex, ...green);
    } else if (green.length) {
      state = 'fixed';
      reasons.push(...[...new Set(green)]);
    } else if (ghsaPkgs.length && !anyGhsaPresent) {
      state = 'not_present';
      reasons.push(`対象パッケージ（${[...new Set(ghsaPkgs.map((p) => `${p.ecosystem} ${p.name}`))].slice(0, 5).join('、')}）は入っていません`);
      if (h.os_id === 'amzn' || h.has_fixed) reasons.push('OSのセキュリティ情報にもこのCVEはありません');
    } else if (kernelHosts.has(h.id)) {
      // provisional: a kernel CVE and this host runs a kernel, but no advisory maps it yet
      state = 'potential';
      reasons.push('Linuxカーネルの脆弱性で、このホストはカーネルを使用中です。まだ配布元の勧告がパッケージに紐づいていないため「要確認（勧告待ち）」です。勧告が出れば自動的に「影響あり」に変わり通知します。');
    } else {
      state = 'unknown';
      if (distroMatched) reasons.push('配布元（Ubuntu）の勧告では、このリリースの該当パッケージは「影響なし」扱いです');
      else if (h.has_fixed) reasons.push('OSのセキュリティ情報（適用済み・未適用）にこのCVEはありません。OSの配布元が未収載か、対象ソフトがOSのパッケージではない可能性があります');
      else reasons.push(`${h.os_name || 'このOS'}では「適用済みの修正」の一覧を取得できないため、OSの観点では判定できません`);
      if (!external.ghsa.length) reasons.push('アプリ依存の脆弱性データベース（GitHub Advisory）に登録がありません');
      else if (!ghsaPkgs.length) reasons.push('GitHub Advisory に登録はありますが、対象パッケージの情報がありません');
    }
    return { hostId: h.id, host: h.name, os: `${h.os_name} ${h.os_version}`.trim(), state, reasons };
  });

  const overall = verdicts.some((v) => v.state === 'affected') ? 'affected'
    : verdicts.length && verdicts.every((v) => v.state !== 'unknown' && v.state !== 'potential') ? 'clear' : 'unknown';
  return { cve, overall, hosts: verdicts, external, kev, watched };
}

// Incremental search over every CVE minisoc2 knows about locally.
export async function searchCves(prefix: string): Promise<{ id: string; where: string[] }[]> {
  const p = prefix.trim().toUpperCase().replace(/[^A-Z0-9-]/g, '');
  if (p.length < 5) return [];
  const rows = await q<{ id: string; src: string }>(
    `SELECT id, src FROM (
       SELECT DISTINCT vuln_id AS id, 'findings' AS src FROM findings WHERE vuln_id LIKE $1
       UNION SELECT DISTINCT vuln_id, 'os_pending' FROM host_os_advisories WHERE vuln_id LIKE $1
       UNION SELECT DISTINCT vuln_id, 'os_fixed' FROM host_fixed_cves WHERE vuln_id LIKE $1
       UNION SELECT cve, 'kev' FROM kev WHERE cve LIKE $1
       UNION SELECT cve, 'watch' FROM watch_cves WHERE cve LIKE $1
       UNION SELECT cve, 'lookup' FROM cve_lookups WHERE cve LIKE $1
       UNION SELECT DISTINCT a, 'osv' FROM vulns, unnest(aliases) a WHERE a LIKE $1
     ) t ORDER BY id DESC LIMIT 200`,
    [`${p}%`],
  );
  const map = new Map<string, Set<string>>();
  for (const r of rows) map.set(r.id, (map.get(r.id) ?? new Set()).add(r.src));
  return [...map.entries()].slice(0, 20).map(([id, s]) => ({ id, where: [...s] }));
}
