-- Distro-tracker confirmed OS vulnerabilities (Ubuntu/Debian) for CVEs not (yet) in OSV. The worker
-- fills this from the distro security tracker for watched CVEs; matching reads it as an OS-advisory
-- candidate source (like dnf updateinfo for RPM), so these become standing findings on __os__, not
-- just one-off alerts.
CREATE TABLE IF NOT EXISTS host_distro_cves (
  host_id   uuid NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
  vuln_id   text NOT NULL,
  pkg       text NOT NULL,
  installed text NOT NULL DEFAULT '',
  fixed     text NOT NULL DEFAULT '',
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (host_id, vuln_id, pkg)
);
