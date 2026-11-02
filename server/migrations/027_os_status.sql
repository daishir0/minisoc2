-- Classify each still-open OS finding by whether the user can act on it NOW:
--   'released' = the vendor has shipped a fixed version > installed  → upgrade resolves it (上げれば直る)
--   'pending'  = the vendor fix is未リリース (pending/needed/deferred) → nothing to apply yet (配布元待ち)
-- Populated by the worker's syncUbuntuOs from the Ubuntu security tracker. Display-only: it does not
-- suppress findings (that is host_os_fixed), it only colour-codes the ones that remain open.
DROP TABLE IF EXISTS host_os_status;
CREATE TABLE host_os_status (
  host_id    uuid NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
  vuln_id    text NOT NULL,
  pkg        text NOT NULL,
  status     text NOT NULL,            -- 'pending' | 'released'
  fixed      text NOT NULL DEFAULT '', -- vendor fixed version (target to upgrade to, when released)
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (host_id, vuln_id, pkg)
);
