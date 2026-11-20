// Source → category, shared by the /logs page and the /api/logs endpoint. raw_logs is the only table with
// a `source` column, so these fragments use a bare `source` (no table alias) — the NOT form would break if
// prefixed. No overlap: access / audit / auth are distinct substrings.
export const CAT = {
  web: "source ~* 'access[_.]log'",
  auth: "source ~* 'auth\\.log|secure|sshd|sudo|fail2ban'",
  audit: "source ~* 'audit'",
  sys: "NOT (source ~* 'access[_.]log|auth\\.log|secure|sshd|sudo|fail2ban|audit')",
} as const;
export type Cat = keyof typeof CAT;
export const CAT_LABEL: Record<string, string> = { web: 'Web', auth: '認証', audit: '監査', sys: 'システム' };
