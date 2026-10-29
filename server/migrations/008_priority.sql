-- Priority model: only KEV and CVSS >= 9.0 are surfaced; everything else stays in detail views.

-- CVSS base scores from NVD (all CVEs, refreshed incrementally) so OS advisories use the same scale.
CREATE TABLE cve_scores (
  cve        text PRIMARY KEY,
  score      numeric(3,1),
  version    text,            -- 4.0 | 3.1 | 3.0 | 2.0
  fetched_at timestamptz NOT NULL DEFAULT now()
);

ALTER TABLE findings ADD COLUMN cvss numeric(3,1);

-- What changed, recorded as it happens; the timeline aggregates it per day. Kept 180 days.
CREATE TABLE change_events (
  id          bigserial PRIMARY KEY,
  ts          timestamptz NOT NULL DEFAULT now(),
  host_id     uuid REFERENCES hosts(id) ON DELETE CASCADE,
  system_root text,
  kind        text NOT NULL,  -- vuln_new | vuln_resolved | kev_added | system_new | host_state | log | feed | health | ops
  important   boolean NOT NULL DEFAULT false,  -- KEV / critical / intrusion sign / monitoring health
  count       int NOT NULL DEFAULT 1,
  title       text NOT NULL,
  detail      text NOT NULL DEFAULT ''
);
CREATE INDEX change_events_ts ON change_events(ts DESC);

-- Open findings per system per day (kept forever; the trend chart reads this).
CREATE TABLE daily_snapshots (
  day         date NOT NULL,
  host_id     uuid NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
  system_root text NOT NULL,
  kev         int NOT NULL DEFAULT 0,
  critical    int NOT NULL DEFAULT 0,
  high        int NOT NULL DEFAULT 0,
  medium      int NOT NULL DEFAULT 0,
  low         int NOT NULL DEFAULT 0,
  PRIMARY KEY (day, host_id, system_root)
);

-- notification scope: KEV + critical is the default
UPDATE settings SET value = jsonb_set(value, '{notifyMinSeverity}', '"critical"') WHERE key = 'policy';
