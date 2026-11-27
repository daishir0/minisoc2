-- Component licenses (per package), for license/obligation review grouped by project (system).
-- host_packages.license: NULL = not yet enriched; '' = looked up but unknown; otherwise an SPDX-ish string.
ALTER TABLE host_packages ADD COLUMN IF NOT EXISTS license text;

-- Cross-ingest cache keyed by (ecosystem, name, version) so re-collection never re-fetches upstream.
-- license '' means "looked up, unknown" (so it is not retried every pass).
CREATE TABLE IF NOT EXISTS license_lookups (
  ecosystem  text NOT NULL,
  name       text NOT NULL,
  version    text NOT NULL,
  license    text NOT NULL DEFAULT '',
  fetched_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (ecosystem, name, version)
);
