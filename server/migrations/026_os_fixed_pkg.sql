-- host_os_fixed must be per (host, CVE, package): a kernel CVE can be fixed for the running flavor
-- (linux-aws) while an unrelated leftover package of a different kernel line is still "needed". Judge
-- each finding's own package against the vendor tracker, not the host as a whole.
DROP TABLE IF EXISTS host_os_fixed;
CREATE TABLE host_os_fixed (
  host_id    uuid NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
  vuln_id    text NOT NULL,
  pkg        text NOT NULL,
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (host_id, vuln_id, pkg)
);
