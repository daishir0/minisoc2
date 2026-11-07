-- Daily file-integrity snapshot + day-over-day diff.
-- The continuous baseline (host_file_baseline, auto-promoted per report) is captured once a day into
-- host_file_snap; the difference from the previous capture is written to host_file_day, so the UI can
-- show "what changed in the last day" at a fixed cadence (the shown diff is at most one day).
CREATE TABLE IF NOT EXISTS host_file_snap (
  host_id uuid NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
  path    text NOT NULL,
  sha     text NOT NULL,
  PRIMARY KEY (host_id, path)
);

CREATE TABLE IF NOT EXISTS host_file_day (
  host_id uuid NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
  day     date NOT NULL,
  path    text NOT NULL,
  kind    text NOT NULL,   -- added | changed | removed
  sev     text NOT NULL,   -- critical | high | medium | low
  PRIMARY KEY (host_id, day, path)
);
CREATE INDEX IF NOT EXISTS host_file_day_day ON host_file_day(day DESC);
