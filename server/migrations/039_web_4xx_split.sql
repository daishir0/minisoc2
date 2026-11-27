-- Split 4xx into its meaningful classes so the signal is actionable:
--   401 spike = credential/auth attack, 404 spike = scanner probing, 403 = blocked (defence working).
-- c4xx stays as the total (kept in sync by ingest) for backward compatibility.
ALTER TABLE web_daily ADD COLUMN IF NOT EXISTS c401 bigint NOT NULL DEFAULT 0;
ALTER TABLE web_daily ADD COLUMN IF NOT EXISTS c403 bigint NOT NULL DEFAULT 0;
ALTER TABLE web_daily ADD COLUMN IF NOT EXISTS c404 bigint NOT NULL DEFAULT 0;
