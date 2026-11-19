-- Per-vhost daily web-traffic aggregates, parsed from access-log lines at ingest time (push and pull
-- hosts both funnel through ingestLogs, so this covers every host that ships an access log). The daily
-- worker compares the latest completed day against the trailing 7-day average to flag traffic spikes,
-- error-rate spikes and a traffic blackout; web_ip_daily backs the "one IP pulled a lot of data" check.
-- web_daily is a permanent aggregate (kept like log_daily); web_ip_daily is pruned to a short window.
CREATE TABLE IF NOT EXISTS web_daily (
  host_id uuid NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
  day     date NOT NULL,
  vhost   text NOT NULL,          -- access-log basename (de-dated), used as the site label
  req     bigint NOT NULL DEFAULT 0,
  c4xx    bigint NOT NULL DEFAULT 0,
  c5xx    bigint NOT NULL DEFAULT 0,
  bytes   bigint NOT NULL DEFAULT 0,
  PRIMARY KEY (host_id, day, vhost)
);
CREATE INDEX IF NOT EXISTS web_daily_day ON web_daily(day DESC);

CREATE TABLE IF NOT EXISTS web_ip_daily (
  host_id uuid NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
  day     date NOT NULL,
  vhost   text NOT NULL,
  ip      text NOT NULL,
  req     bigint NOT NULL DEFAULT 0,
  bytes   bigint NOT NULL DEFAULT 0,
  PRIMARY KEY (host_id, day, vhost, ip)
);
CREATE INDEX IF NOT EXISTS web_ip_daily_day ON web_ip_daily(day DESC);
