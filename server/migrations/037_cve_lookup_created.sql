-- Record when a CVE was first looked up / registered on the 照会 screen (distinct from fetched_at, which is
-- refreshed on every re-lookup). The upsert only touches data + fetched_at, so created_at stays at the first
-- insert. Backfill existing rows to their last-fetched time (the best approximation we have).
ALTER TABLE cve_lookups ADD COLUMN IF NOT EXISTS created_at timestamptz NOT NULL DEFAULT now();
UPDATE cve_lookups SET created_at = fetched_at WHERE created_at > fetched_at;
