-- AIDE-style file-integrity baseline, kept server-side so hosts stay read-only. Each report's file
-- hashes are diffed against this baseline; differences become change events/alerts and the baseline
-- is then auto-promoted (updated to the newly reported state). The first report sets the baseline
-- quietly. A partial scan (budget hit) is diffed but does not delete "missing" files.
CREATE TABLE host_file_baseline (
  host_id uuid NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
  path    text NOT NULL,
  sha     text NOT NULL,
  size    bigint NOT NULL,
  mtime   bigint NOT NULL,
  PRIMARY KEY (host_id, path)
);

-- when the integrity baseline was first established (null until the first scan arrives)
ALTER TABLE hosts ADD COLUMN file_baseline_at timestamptz;
