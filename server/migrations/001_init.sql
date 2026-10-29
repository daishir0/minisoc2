-- minisoc2 schema v1: hosts, inventory, vulnerabilities, findings, alerts, admin.

CREATE TABLE settings (
  key   text PRIMARY KEY,
  value jsonb NOT NULL
);

CREATE TABLE admin_users (
  id            serial PRIMARY KEY,
  email         text NOT NULL UNIQUE,
  password_hash text NOT NULL,
  created_at    timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE sessions (
  token_hash text PRIMARY KEY,
  user_id    int NOT NULL REFERENCES admin_users(id) ON DELETE CASCADE,
  expires_at timestamptz NOT NULL
);

CREATE TABLE enroll_tokens (
  id         serial PRIMARY KEY,
  token_hash text NOT NULL UNIQUE,
  label      text NOT NULL DEFAULT '',
  max_uses   int NOT NULL DEFAULT 1,
  uses       int NOT NULL DEFAULT 0,
  expires_at timestamptz NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE hosts (
  id              uuid PRIMARY KEY,
  name            text NOT NULL,           -- editable display name (defaults to hostname)
  hostname        text NOT NULL,
  token_hash      text NOT NULL,
  platform        text NOT NULL DEFAULT '',
  os_name         text NOT NULL DEFAULT '',
  os_version      text NOT NULL DEFAULT '',
  os_id           text NOT NULL DEFAULT '',
  kernel          text NOT NULL DEFAULT '',
  arch            text NOT NULL DEFAULT '',
  agent_version   text NOT NULL DEFAULT '',
  enrolled_at     timestamptz NOT NULL DEFAULT now(),
  last_seen_at    timestamptz,
  stale_alerted   boolean NOT NULL DEFAULT false,
  baseline_done   boolean NOT NULL DEFAULT false, -- first report sets the baseline without per-finding alerts
  needs_match     boolean NOT NULL DEFAULT false,
  disabled        boolean NOT NULL DEFAULT false,
  state           jsonb NOT NULL DEFAULT '{}'::jsonb -- latest ports/users/file hashes
);

-- One row per report received (small; the payload itself is not kept).
CREATE TABLE reports (
  id            bigserial PRIMARY KEY,
  host_id       uuid NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
  received_at   timestamptz NOT NULL DEFAULT now(),
  agent_version text NOT NULL,
  duration_ms   int NOT NULL,
  package_count int NOT NULL,
  advisory_count int,
  errors        jsonb NOT NULL DEFAULT '[]'::jsonb,
  update_info   jsonb
);
CREATE INDEX reports_host_time ON reports(host_id, received_at DESC);

-- Latest inventory per host (replaced on every report).
CREATE TABLE host_packages (
  host_id   uuid NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
  ecosystem text NOT NULL,
  name      text NOT NULL,
  version   text NOT NULL,
  sources   text[] NOT NULL,
  PRIMARY KEY (host_id, ecosystem, name, version)
);
CREATE INDEX host_packages_pkg ON host_packages(ecosystem, name, version);

-- Pending security updates reported by the OS package manager (dnf updateinfo).
CREATE TABLE host_os_advisories (
  host_id  uuid NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
  vuln_id  text NOT NULL,
  advisory text,
  severity text NOT NULL,
  pkg      text NOT NULL,
  fixed    text NOT NULL,
  PRIMARY KEY (host_id, vuln_id, pkg)
);

-- OSV query cache: which vulnerabilities affect a package version.
CREATE TABLE pkg_vuln_cache (
  ecosystem  text NOT NULL,
  name       text NOT NULL,
  version    text NOT NULL,
  vuln_ids   text[] NOT NULL,
  checked_at timestamptz NOT NULL,
  PRIMARY KEY (ecosystem, name, version)
);

CREATE TABLE vulns (
  id         text PRIMARY KEY,  -- OSV id (GHSA-..., PYSEC-...) or CVE id
  aliases    text[] NOT NULL DEFAULT '{}',
  summary    text NOT NULL DEFAULT '',
  severity   text NOT NULL DEFAULT 'unknown', -- critical | high | medium | low | unknown
  cvss       numeric,
  published  timestamptz,
  modified   timestamptz,
  fixed      jsonb NOT NULL DEFAULT '{}'::jsonb, -- "ecosystem/name" -> [fixed versions]
  fetched_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE kev (
  cve        text PRIMARY KEY,
  vendor     text NOT NULL,
  product    text NOT NULL,
  name       text NOT NULL,
  date_added date NOT NULL,
  due_date   date,
  ransomware text
);

CREATE TABLE feed_status (
  name         text PRIMARY KEY,
  last_success timestamptz,
  last_error   text,
  last_error_at timestamptz,
  item_count   int
);

CREATE TABLE findings (
  id            bigserial PRIMARY KEY,
  host_id       uuid NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
  vuln_id       text NOT NULL,          -- CVE preferred, else OSV id
  ecosystem     text NOT NULL,
  pkg           text NOT NULL,
  version       text NOT NULL,
  fixed         text NOT NULL DEFAULT '',
  severity      text NOT NULL,
  kev           boolean NOT NULL DEFAULT false,
  source        text NOT NULL,          -- osv | os-advisory
  status        text NOT NULL DEFAULT 'open', -- open | resolved | suppressed
  first_seen    timestamptz NOT NULL DEFAULT now(),
  last_seen     timestamptz NOT NULL DEFAULT now(),
  resolved_at   timestamptz,
  suppress_reason text,                 -- VEX justification
  suppress_note text,
  suppressed_at timestamptz,
  UNIQUE (host_id, vuln_id, ecosystem, pkg)
);
CREATE INDEX findings_open ON findings(status, severity);

CREATE TABLE watch_cves (
  cve        text PRIMARY KEY,
  note       text NOT NULL DEFAULT '',
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE alerts (
  id         bigserial PRIMARY KEY,
  kind       text NOT NULL,      -- vuln | kev | watch | stale | feed | baseline | agent
  severity   text NOT NULL,      -- critical | high | medium | low | info
  host_id    uuid REFERENCES hosts(id) ON DELETE CASCADE,
  title      text NOT NULL,
  detail     text NOT NULL DEFAULT '',
  dedupe_key text NOT NULL UNIQUE,
  status     text NOT NULL DEFAULT 'open', -- open | ack | resolved
  created_at timestamptz NOT NULL DEFAULT now(),
  notified_at timestamptz,
  notify_error text
);
CREATE INDEX alerts_status ON alerts(status, created_at DESC);
