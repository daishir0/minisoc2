// Shared e-mail formatting so the immediate mail and the daily digest render vulnerabilities identically:
// one line per CVE, sorted by priority, with the CVE id + title, EPSS, when it was made public to the
// world (+ how many days ago) and when WE first detected it on the host. Generic / no host-specifics.
import { riskScore } from './risk';

export interface CveRow {
  vuln_id: string; pkg: string; version: string; fixed: string; severity: string; kev: boolean;
  is_new?: boolean; detected?: string | null; summary?: string | null; published?: string | null; epss?: number | null; pub?: boolean;
  pkgs?: string[]; // set by groupByCve: all packages this CVE+fix affects on the host (collapses httpd/httpd-core/… into one line)
}

const SEV_LABEL: Record<string, string> = { critical: '緊急', high: '高', medium: '中', low: '低' };
const SEV_RANK: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3 };

// SQL columns (and joins) that produce a CveRow. Reused verbatim by both mails so the shape never drifts.
// `$S` is the "since" param placeholder index the caller substitutes for the is_new flag.
export const CVE_SELECT = (sinceParam: string) => `
  f.vuln_id, f.pkg, f.version, f.fixed, f.severity, f.kev,
  (f.first_seen >= ${sinceParam}) AS is_new,
  to_char(f.first_seen, 'MM/DD HH24:MI') AS detected,
  v.summary, to_char(v.published, 'YYYY-MM-DD') AS published,
  (SELECT max(e.score) FROM epss e WHERE e.cve=f.vuln_id OR e.cve = ANY(SELECT unnest(aliases) FROM vulns vv WHERE vv.id=f.vuln_id)) AS epss,
  EXISTS(SELECT 1 FROM systems s WHERE s.host_id=f.host_id AND s.root = ANY(f.systems) AND s.exposure='public') AS pub`;
export const CVE_JOIN = `LEFT JOIN LATERAL (SELECT summary, published FROM vulns v WHERE v.id=f.vuln_id OR f.vuln_id = ANY(v.aliases) ORDER BY published DESC NULLS LAST LIMIT 1) v ON true`;

export const cveScore = (r: CveRow) => riskScore({ kev: r.kev, epss: r.epss ?? null, exposure: r.pub ? 'public' : '', severity: r.severity });
export const cveSort = (a: CveRow, b: CveRow) => cveScore(b) - cveScore(a) || Number(b.is_new) - Number(a.is_new) || ((SEV_RANK[a.severity] ?? 9) - (SEV_RANK[b.severity] ?? 9));

const daysAgo = (d: string | null) => (d ? Math.max(0, Math.round((Date.now() - new Date(d + 'T00:00:00Z').getTime()) / 86400_000)) : null);
const cveId = (v: string) => v.replace(/^(UBUNTU|DEBIAN)-/, '');

// Collapse all rows of the SAME CVE into one entry, gathering every affected package name so a CVE that
// touches httpd / httpd-core / httpd-filesystem / httpd-tools / mod_http2 / mod_ssl shows as ONE line.
// is_new is OR-ed; the highest-priority row supplies the shared CVE metadata and the shown version→fix
// (packages of one CVE almost always share the fix; any epoch/version nuance is on the host page).
export function groupByCve(rows: CveRow[]): CveRow[] {
  const by = new Map<string, CveRow>();
  for (const r of rows) {
    const key = cveId(r.vuln_id);
    const g = by.get(key);
    if (!g) by.set(key, { ...r, pkgs: [r.pkg], is_new: !!r.is_new });
    else {
      if (r.pkg && !g.pkgs!.includes(r.pkg)) g.pkgs!.push(r.pkg);
      g.is_new = g.is_new || r.is_new;
      if (cveScore(r) > cveScore(g)) { g.severity = r.severity; g.kev = r.kev; g.version = r.version; g.fixed = r.fixed; }
    }
  }
  return [...by.values()];
}

// How the collapsed package set reads on the fix line.
const pkgLabel = (pkgs: string[]) =>
  pkgs.length <= 1 ? (pkgs[0] ?? '') : pkgs.length <= 3 ? pkgs.join(', ') : `${pkgs[0]} ほか${pkgs.length - 1}パッケージ`;

// Three text lines for one CVE (number, title+epss / publish+detect / package→fix).
export function cveLines(r: CveRow, i: number): string[] {
  const tag = `${r.kev ? 'KEV' : SEV_LABEL[r.severity] ?? r.severity}${r.is_new ? '🆕' : ''}`;
  const sm = (r.summary ?? '').replace(/\s+/g, ' ').trim();
  const title = sm ? (sm.length > 60 ? sm.slice(0, 60) + '…' : sm) : '(タイトル情報なし)';
  const da = daysAgo(r.published ?? null);
  const pub = r.published ? `公開 ${r.published}${da != null ? `（${da}日前）` : ''}` : '公開日 不明';
  const epss = r.epss != null ? ` ・ EPSS ${Math.round(r.epss * 100)}%` : '';
  const fix = r.fixed ? `${r.version.split(',')[0].slice(0, 24)} → ${r.fixed.split(',')[0].slice(0, 24)}` : `${r.version.split(',')[0].slice(0, 24)}（修正版は要確認）`;
  const pkgs = r.pkgs && r.pkgs.length ? r.pkgs : [r.pkg];
  return [
    `  ${i + 1}. [${tag}] ${cveId(r.vuln_id)}  ${title}${epss}`,
    `      ${pub}${r.detected ? ` ／ 当システム検出 ${r.detected}` : ''}`,
    `      ${pkgLabel(pkgs)} ${fix}`,
  ];
}

// Host-wide monitoring / intrusion signals, one line per host (kind counts).
const OPS_KIND: Record<string, string> = { state: 'ホスト状態の変化', log: 'ログ脅威', stale: '報告停止', feed: 'フィード', disk: 'ディスク', agent: 'エージェント', baseline: '基準線' };
export function opsLine(host: string, kinds: { kind: string; n: number }[]): string {
  return `  ・${host}：${kinds.map((k) => `${OPS_KIND[k.kind] ?? k.kind} ${k.n}`).join('・')}`;
}
