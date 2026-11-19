import { q } from './db';

// An alert "needs attention" when it is an open monitoring / detection signal. Vulnerability alerts
// (vuln/kev) are only e-mail triggers — the standing vulnerability list is `findings` (the 脆弱性 tab,
// counted from finding status), so they are excluded here to avoid double-counting and the stale pile-up
// of alert rows whose findings were long resolved.
export const IMPORTANT_ALERT = "kind NOT IN ('vuln','kev') AND (severity='critical' OR kind IN ('watch','stale','feed','disk'))";

// Counts shown as navigation badges, gathered in one query so the layout and the sub-tab strip can both
// show "how much needs attention" before the user drills in. All generic (no host-specifics).
export interface NavCounts {
  detectAlerts: number; // open important alerts (top-level 検知 + the アラート sub-tab)
  staleHosts: number;   // hosts that stopped reporting (top-level 資産)
  vuln: number;         // open KEV・緊急 findings (脆弱性 sub-tab)
  logThreat: number;    // log threats in the last 24h (ログ脅威 sub-tab)
  fileChange: number;   // un-acked CRITICAL file changes (identity/keys/sudoers) in the recent window (ファイル改ざん sub-tab)
}

export async function navCounts(): Promise<NavCounts> {
  const [r] = await q<{ d: string; s: string; v: string; l: string; f: string }>(
    `SELECT
       (SELECT count(*) FROM alerts WHERE status='open' AND ${IMPORTANT_ALERT}) AS d,
       (SELECT count(*) FROM hosts WHERE stale_alerted AND NOT disabled) AS s,
       (SELECT count(*) FROM findings WHERE status='open' AND (kev OR severity='critical')) AS v,
       (SELECT count(*) FROM alerts WHERE kind='log' AND status='open' AND created_at > now() - interval '24 hours') AS l,
       (SELECT count(*) FROM host_file_day WHERE day > current_date - 30 AND sev='critical' AND acked_at IS NULL) AS f`,
  );
  return {
    detectAlerts: Number(r?.d ?? 0), staleHosts: Number(r?.s ?? 0), vuln: Number(r?.v ?? 0),
    logThreat: Number(r?.l ?? 0), fileChange: Number(r?.f ?? 0),
  };
}
