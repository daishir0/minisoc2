-- OSV lists many Ubuntu/Debian OS (kernel) CVEs WITHOUT a fixed version, so minisoc2 can't tell they
-- are already patched and shows them as open forever (false positives). The worker consults the distro
-- security tracker (the vendor authority) and records here the CVEs it confirms are FIXED on this host
-- (installed >= the vendor's released fix). Matching then suppresses the matching OSV OS findings.
CREATE TABLE IF NOT EXISTS host_os_fixed (
  host_id    uuid NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
  vuln_id    text NOT NULL,
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (host_id, vuln_id)
);
