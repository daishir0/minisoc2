// On-demand breakdown of a web-access spike: parse the raw access-log lines minisoc2 already stores
// (raw_logs) for a given host+day, split by vhost, and classify what the spike actually is — scanner
// reconnaissance, a credential/auth attack, ordinary app 4xx (broken links), a real traffic rise, or an
// actual breach (a secret path that returned 200). Shared by the daily web-anomaly job (to raise ONE
// correctly-worded alert with the breakdown), by the log-threat investigation prompt, and by the UI.
import { q } from './db';

// Paths a scanner hits looking for secrets / admin panels / known-vuln endpoints. Hitting these is recon;
// getting a 200 on one is a real leak.
export const RECON_RE = /(\.env|\.git\b|\.git\/|\.aws|\.ssh|\/\.svn|\/\.hg|\/\.DS_Store|phpinfo|\/info\.php|pinfo\.php|pi\.php|php\.php|test\.php|_environment|server-status|server-info|\/actuator|\/wp-login|\/wp-admin|\/xmlrpc\.php|\/vendor\/|credentials|config\.(php|json|yml|yaml)|\/phpmyadmin|\/pma\b|\/adminer|eval-stdin|\/boaform|\/cgi-bin|\/\.aws\/|\/solr\/|\/console\b)/i;
// The subset whose exposure (status 200) is an actual data leak.
const SENSITIVE_RE = /(\.env|\.git\/config|\.aws|\.ssh|credentials|phpinfo|_environment)/i;

// Request path out of a CLF line: ip ... "METHOD path proto" status bytes
const CLF_PATH = /^(\S+) \S+ \S+ \[(\d{2})\/([A-Za-z]{3})\/(\d{4}):[^\]]*\] "[A-Z]+ (\S+) [^"]*" (\d{3}) (\d+|-)/;
const MON: Record<string, string> = { Jan: '01', Feb: '02', Mar: '03', Apr: '04', May: '05', Jun: '06', Jul: '07', Aug: '08', Sep: '09', Oct: '10', Nov: '11', Dec: '12' };
const ACCESS_SRC = /access[_.]log$/;
function vhostOf(source: string): string {
  let b = source.replace(/^file:/, '');
  b = b.slice(b.lastIndexOf('/') + 1).replace(/\.gz$/, '').replace(/[-.]\d{8}$/, '');
  return b.slice(0, 200);
}

export type WebClass = 'breach' | 'auth' | 'recon' | 'app-errors' | 'traffic';
export interface WebDayAnalysis {
  vhost: string; total: number;
  status: { c2: number; c3: number; c401: number; c403: number; c404: number; c4xx: number; c5xx: number };
  topIps: [string, number][]; topPaths: [string, number][]; top4xxPaths: [string, number][];
  recon: number; sensitive200: { ip: string; path: string }[];
  cls: WebClass;
}

export const WEB_CLASS_LABEL: Record<WebClass, string> = {
  breach: '情報漏洩の疑い（機微パスに200）', auth: '認証攻撃の疑い（401集中）',
  recon: '偵察（スキャナ探索・ほぼ遮断）', 'app-errors': 'アプリの4xx（リンク切れ/API等）', traffic: 'アクセス増加',
};

function classify(a: Omit<WebDayAnalysis, 'cls'>): WebClass {
  const s = a.status;
  if (a.sensitive200.length > 0) return 'breach';
  const c4 = s.c4xx || 1;
  if (s.c401 >= 20 && s.c401 >= 0.4 * c4) return 'auth';
  // recon: most of the 4xx are probes for secret/known paths, and nothing leaked
  if (s.c4xx > 0 && a.recon >= 0.4 * s.c4xx) return 'recon';
  if (s.c4xx >= 0.5 * Math.max(a.total, 1)) return 'app-errors';
  return 'traffic';
}

// Analyse all access-log vhosts of a host for one day, from raw_logs. Returns per-vhost breakdown.
// Returns an empty map when raw logs are unavailable (e.g. raw ingest disabled / retention) — callers
// then fall back to the plain web_daily counts.
export async function analyzeWebDay(hostId: string, day: string, cap = 40000): Promise<Map<string, WebDayAnalysis>> {
  const rows = await q<{ source: string; message: string }>(
    `SELECT source, message FROM raw_logs
     WHERE host_id=$1 AND source ~* 'access[_.]log' AND received_at >= $2::date AND received_at < $2::date + 2
     LIMIT $3`, [hostId, day, cap]);
  const [yy, mm, dd] = day.split('-');
  const acc = new Map<string, { total: number; c2: number; c3: number; c401: number; c403: number; c404: number; c4xx: number; c5xx: number; ip: Map<string, number>; path: Map<string, number>; p4: Map<string, number>; recon: number; sens: { ip: string; path: string }[] }>();
  for (const r of rows) {
    if (!ACCESS_SRC.test(vhostOf(r.source))) continue;
    const m = CLF_PATH.exec(r.message);
    if (!m) continue;
    const [, ip, ld, lmon, ly, path, st] = m;
    if (ly !== yy || MON[lmon] !== mm || ld !== dd) continue; // keep only this day's lines
    const vhost = vhostOf(r.source);
    const g = acc.get(vhost) ?? { total: 0, c2: 0, c3: 0, c401: 0, c403: 0, c404: 0, c4xx: 0, c5xx: 0, ip: new Map<string, number>(), path: new Map<string, number>(), p4: new Map<string, number>(), recon: 0, sens: [] as { ip: string; path: string }[] };
    g.total++;
    const status = Number(st);
    if (status >= 200 && status < 300) g.c2++;
    else if (status >= 300 && status < 400) g.c3++;
    else if (status >= 400 && status < 500) { g.c4xx++; if (status === 401) g.c401++; else if (status === 403) g.c403++; else if (status === 404) g.c404++; }
    else if (status >= 500) g.c5xx++;
    g.ip.set(ip, (g.ip.get(ip) ?? 0) + 1);
    const pth = path.split('?')[0].slice(0, 120);
    g.path.set(pth, (g.path.get(pth) ?? 0) + 1);
    if (status >= 400 && status < 500) g.p4.set(pth, (g.p4.get(pth) ?? 0) + 1);
    // Match the PATH only (not the query): scanners probe `GET /.env`, while legitimate file-transfer APIs
    // carry filenames in the query (`/api/fs?path=....ssh`) and must not be mistaken for a secret probe.
    if (RECON_RE.test(pth)) { g.recon++; if (status >= 200 && status < 300 && SENSITIVE_RE.test(pth)) g.sens.push({ ip, path: pth }); }
    acc.set(vhost, g);
  }
  const out = new Map<string, WebDayAnalysis>();
  const top = (m: Map<string, number>, n: number): [string, number][] => [...m.entries()].sort((a, b) => b[1] - a[1]).slice(0, n);
  for (const [vhost, g] of acc) {
    const base: Omit<WebDayAnalysis, 'cls'> = {
      vhost, total: g.total,
      status: { c2: g.c2, c3: g.c3, c401: g.c401, c403: g.c403, c404: g.c404, c4xx: g.c4xx, c5xx: g.c5xx },
      topIps: top(g.ip, 5), topPaths: top(g.path, 5), top4xxPaths: top(g.p4, 5),
      recon: g.recon, sensitive200: g.sens.slice(0, 5),
    };
    out.set(vhost, { ...base, cls: classify(base) });
  }
  return out;
}

// Human-readable breakdown lines (for alert detail / investigation prompt).
export function renderBreakdown(a: WebDayAnalysis): string[] {
  const s = a.status;
  const statusBits = [s.c2 && `2xx ${s.c2}`, s.c3 && `3xx ${s.c3}`, s.c401 && `401 ${s.c401}`, s.c403 && `403 ${s.c403}`, s.c404 && `404 ${s.c404}`, s.c5xx && `5xx ${s.c5xx}`].filter(Boolean).join(' / ');
  const lines = [
    `判定：${WEB_CLASS_LABEL[a.cls]}`,
    `総リクエスト ${a.total}（${statusBits || '—'}）`,
    `上位IP：${a.topIps.map(([ip, n]) => `${ip}(${n})`).join('、') || '—'}`,
    `上位4xxパス：${a.top4xxPaths.map(([p, n]) => `${p}(${n})`).join('、') || '—'}`,
  ];
  if (a.recon > 0) lines.push(`探索パス検出：${a.recon}件（.env/.git/phpinfo 等）`);
  if (a.sensitive200.length) lines.push(`⚠機微パスに200：${a.sensitive200.map((x) => `${x.path}←${x.ip}`).join('、')}`);
  return lines;
}
