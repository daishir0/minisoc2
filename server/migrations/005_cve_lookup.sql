-- Security advisories already applied on a host (evidence that a CVE is fixed there).
CREATE TABLE host_fixed_cves (
  host_id  uuid NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
  vuln_id  text NOT NULL,
  severity text NOT NULL,
  pkg      text NOT NULL,
  fixed    text NOT NULL,
  PRIMARY KEY (host_id, vuln_id, pkg)
);
CREATE INDEX host_fixed_cves_vuln ON host_fixed_cves(vuln_id);

-- Cached external lookups for a single CVE (NVD + GitHub Advisory Database).
CREATE TABLE cve_lookups (
  cve        text PRIMARY KEY,
  fetched_at timestamptz NOT NULL DEFAULT now(),
  data       jsonb NOT NULL
);

CREATE INDEX host_os_advisories_vuln ON host_os_advisories(vuln_id);
CREATE INDEX findings_vuln ON findings(vuln_id);
