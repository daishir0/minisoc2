-- Give a watched CVE a lifecycle so it stops costing matching + per-CVE external lookups once it is dealt
-- with. 'watching' = actively tracked (full cost); 'resolved' = was detected on a host and is now cleared
-- everywhere (auto-set by the worker; dropped from the heavy external-lookup loops, revived automatically
-- if it re-appears open); 'archived' = the user retired it (excluded from all matching and lookups, kept
-- for history). Deletion still removes it entirely.
ALTER TABLE watch_cves ADD COLUMN IF NOT EXISTS status text NOT NULL DEFAULT 'watching'; -- watching | resolved | archived
ALTER TABLE watch_cves ADD COLUMN IF NOT EXISTS resolved_at timestamptz;
ALTER TABLE watch_cves ADD COLUMN IF NOT EXISTS archived_at timestamptz;
