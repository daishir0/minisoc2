-- Per-system "not affected" (VEX): a judgment that a CVE is not exploitable in ONE specific system,
-- even when the same package (finding) is shared by several systems on the host. Matching removes the
-- judged system from that finding's systems[], so other systems keep the finding (and their counts).
CREATE TABLE IF NOT EXISTS finding_vex (
  id          bigserial PRIMARY KEY,
  host_id     uuid NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
  system_root text NOT NULL,
  vuln_id     text NOT NULL,
  ecosystem   text NOT NULL,
  pkg         text NOT NULL,
  reason      text NOT NULL,          -- CycloneDX justification
  note        text,
  created_by  text,
  created_at  timestamptz NOT NULL DEFAULT now(),
  UNIQUE (host_id, system_root, vuln_id, ecosystem, pkg)
);
CREATE INDEX IF NOT EXISTS finding_vex_host ON finding_vex(host_id);
