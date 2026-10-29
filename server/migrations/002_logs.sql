-- Log monitoring: raw logs (daily partitions, dropped after the retention period),
-- permanent daily aggregates, rule hits and "first seen" values.

CREATE TABLE raw_logs (
  host_id     uuid NOT NULL,
  received_at timestamptz NOT NULL DEFAULT now(),
  ts          timestamptz,          -- time in the log line when known
  source      text NOT NULL,        -- journal:<unit> | file:<path> | app:<name>
  message     text NOT NULL
) PARTITION BY RANGE (received_at);
-- partitions raw_logs_YYYYMMDD (UTC days) are created on demand (see src/lib/logs.ts)
CREATE INDEX raw_logs_host_time ON raw_logs(host_id, received_at DESC);

CREATE TABLE log_daily (
  host_id uuid NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
  day     date NOT NULL,
  source  text NOT NULL,
  lines   bigint NOT NULL DEFAULT 0,
  bytes   bigint NOT NULL DEFAULT 0,
  PRIMARY KEY (host_id, day, source)
);

CREATE TABLE log_hits (
  id      bigserial PRIMARY KEY,
  host_id uuid NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
  rule_id text NOT NULL,
  ts      timestamptz NOT NULL,
  grp     text NOT NULL DEFAULT '',   -- grouping value (IP, user ...)
  sample  text NOT NULL
);
CREATE INDEX log_hits_rule_time ON log_hits(rule_id, host_id, ts DESC);

CREATE TABLE log_rule_daily (
  host_id uuid NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
  day     date NOT NULL,
  rule_id text NOT NULL,
  hits    bigint NOT NULL DEFAULT 0,
  PRIMARY KEY (host_id, day, rule_id)
);

CREATE TABLE log_seen (
  host_id    uuid NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
  kind       text NOT NULL,     -- e.g. ssh_ip, sudo_user
  value      text NOT NULL,
  first_seen timestamptz NOT NULL DEFAULT now(),
  last_seen  timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (host_id, kind, value)
);

CREATE TABLE log_batches (
  id          bigserial PRIMARY KEY,
  host_id     uuid NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
  received_at timestamptz NOT NULL DEFAULT now(),
  lines       int NOT NULL,
  bytes       int NOT NULL,
  stored_raw  boolean NOT NULL,
  truncated   int NOT NULL DEFAULT 0
);
CREATE INDEX log_batches_host_time ON log_batches(host_id, received_at DESC);
