-- Observed source addresses per agent host, so operators can see where an agent actually connects from and
-- pin the allow list to it with one click (instead of typing the IP). Populated on every authenticated push
-- / check-in / enrollment; recorded even when the IP is currently rejected, so a changed address is still
-- visible for recovery. hosts.last_ip is the most recent peer; host_seen_ips keeps the recent distinct set.
ALTER TABLE hosts ADD COLUMN IF NOT EXISTS last_ip inet;

CREATE TABLE IF NOT EXISTS host_seen_ips (
  host_id    uuid NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
  ip         inet NOT NULL,
  first_seen timestamptz NOT NULL DEFAULT now(),
  last_seen  timestamptz NOT NULL DEFAULT now(),
  count      bigint NOT NULL DEFAULT 1,
  PRIMARY KEY (host_id, ip)
);
CREATE INDEX IF NOT EXISTS host_seen_ips_recent ON host_seen_ips(host_id, last_seen DESC);
