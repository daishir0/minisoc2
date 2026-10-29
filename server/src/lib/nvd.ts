// NVD CVSS scores for every CVE, so OS advisories (whose vendor severity is not CVSS) are judged
// on the same 0-10 scale. First a full backfill (newest windows first), then incremental updates
// by last-modified date. Progress is stored so a restart resumes where it stopped.
import { markFeed } from './feeds';
import { q } from './db';
import { getSetting, setSetting } from './settings';

const API = 'https://services.nvd.nist.gov/rest/json/cves/2.0';
const PAGE = 2000;
const WINDOW_DAYS = 120; // NVD limit for one date range
const EARLIEST = Date.parse('1999-01-01T00:00:00Z');

interface SyncState {
  fullDone: boolean;
  windowEnd: string; // backfill: current window end (moves backwards)
  startIndex: number;
  incFrom?: string; // incremental: last-modified lower bound
}

type Metric = { cvssData: { baseScore: number } };
interface NvdItem { cve: { id: string; metrics?: Record<string, Metric[]> } }

function pickScore(m: Record<string, Metric[]> | undefined): { score: number | null; version: string | null } {
  if (!m) return { score: null, version: null };
  for (const [key, version] of [['cvssMetricV31', '3.1'], ['cvssMetricV40', '4.0'], ['cvssMetricV30', '3.0'], ['cvssMetricV2', '2.0']] as const) {
    const s = m[key]?.[0]?.cvssData?.baseScore;
    if (typeof s === 'number') return { score: s, version };
  }
  return { score: null, version: null };
}

async function fetchPage(params: Record<string, string>): Promise<{ total: number; items: NvdItem[] }> {
  const url = `${API}?${new URLSearchParams({ ...params, resultsPerPage: String(PAGE) })}`;
  const ac = new AbortController();
  const t = setTimeout(() => ac.abort(), 240_000);
  try {
    const res = await fetch(url, { signal: ac.signal, headers: { 'user-agent': 'minisoc2', ...(process.env.NVD_API_KEY ? { apiKey: process.env.NVD_API_KEY } : {}) } });
    if (!res.ok) throw new Error(`NVD HTTP ${res.status}`);
    const j = (await res.json()) as { totalResults: number; vulnerabilities: NvdItem[] };
    return { total: j.totalResults, items: j.vulnerabilities ?? [] };
  } finally {
    clearTimeout(t);
  }
}

async function store(items: NvdItem[]): Promise<void> {
  const rows = items.map((v) => ({ id: v.cve.id, ...pickScore(v.cve.metrics) }));
  for (let i = 0; i < rows.length; i += 2000) {
    const ch = rows.slice(i, i + 2000);
    await q(
      `INSERT INTO cve_scores(cve, score, version, fetched_at) SELECT c, s, v, now() FROM unnest($1::text[], $2::numeric[], $3::text[]) AS t(c, s, v)
       ON CONFLICT (cve) DO UPDATE SET score=EXCLUDED.score, version=EXCLUDED.version, fetched_at=now()`,
      [ch.map((r) => r.id), ch.map((r) => r.score), ch.map((r) => r.version)],
    );
  }
}

const iso = (ms: number) => new Date(ms).toISOString().replace('Z', '').slice(0, 23) + 'Z';

// One API request per call. Returns true while there is more to fetch right away.
export async function nvdStep(): Promise<boolean> {
  const st = await getSetting<SyncState>('nvd_sync', { fullDone: false, windowEnd: new Date().toISOString(), startIndex: 0 });
  try {
    if (!st.fullDone) {
      const end = Date.parse(st.windowEnd);
      const start = Math.max(EARLIEST, end - WINDOW_DAYS * 86400_000);
      const page = await fetchPage({ pubStartDate: iso(start), pubEndDate: iso(end), startIndex: String(st.startIndex) });
      await store(page.items);
      const next = st.startIndex + PAGE;
      if (next < page.total) await setSetting('nvd_sync', { ...st, startIndex: next });
      else if (start <= EARLIEST) await setSetting('nvd_sync', { fullDone: true, windowEnd: st.windowEnd, startIndex: 0, incFrom: st.incFrom ?? new Date().toISOString() });
      else await setSetting('nvd_sync', { ...st, windowEnd: new Date(start).toISOString(), startIndex: 0, incFrom: st.incFrom ?? new Date().toISOString() });
      await markFeed('nvd', true, { count: Number((await q<{ n: string }>('SELECT count(*) AS n FROM cve_scores'))[0].n) });
      return true;
    }
    const from = Date.parse(st.incFrom ?? new Date(Date.now() - 86400_000).toISOString()) - 3600_000;
    const to = Math.min(Date.now(), from + WINDOW_DAYS * 86400_000);
    if (Date.now() - from < 3 * 3600_000 && st.startIndex === 0) return false; // up to date (checks every few hours)
    const page = await fetchPage({ lastModStartDate: iso(from), lastModEndDate: iso(to), startIndex: String(st.startIndex) });
    await store(page.items);
    const next = st.startIndex + PAGE;
    if (next < page.total) await setSetting('nvd_sync', { ...st, startIndex: next });
    else await setSetting('nvd_sync', { ...st, startIndex: 0, incFrom: new Date(to).toISOString() });
    await markFeed('nvd', true, { count: Number((await q<{ n: string }>('SELECT count(*) AS n FROM cve_scores'))[0].n) });
    return next < page.total;
  } catch (e) {
    await markFeed('nvd', false, { error: e instanceof Error ? e.message : String(e) });
    return false;
  }
}

// NVD allows 5 requests / 30 s without an API key and 50 with one.
export const NVD_DELAY_MS = process.env.NVD_API_KEY ? 1_000 : 7_000;
