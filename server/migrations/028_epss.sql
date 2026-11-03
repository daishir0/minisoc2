-- EPSS (Exploit Prediction Scoring System, FIRST.org): probability a CVE is exploited in the next 30 days.
-- Keyed by CVE. Our vulns.id are mostly OSV/GHSA ids (CVE lives in vulns.aliases) and OS findings carry
-- the CVE directly, so EPSS is kept in its own table and resolved per finding by CVE. Populated daily by
-- the worker's syncEpss(), bounded to the CVEs that actually appear in this environment.
CREATE TABLE IF NOT EXISTS epss (
  cve        text PRIMARY KEY,
  score      real NOT NULL,          -- 0..1 probability
  pct        real,                   -- percentile within all CVEs
  updated_at timestamptz NOT NULL DEFAULT now()
);
