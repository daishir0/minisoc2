-- Per-host allowed source IPs/CIDRs. Empty = no restriction (falls back to the global default in
-- settings key 'net_policy'). Enforced at the ingest API (report/logs), behind the reverse proxy.
ALTER TABLE hosts ADD COLUMN allowed_ips text[] NOT NULL DEFAULT '{}';
