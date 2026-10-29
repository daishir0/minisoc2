-- Remediation tasks: one row per (host, system). The work items themselves are computed from
-- open KEV/critical findings; this table only keeps the human workflow state.
CREATE TABLE tasks (
  host_id     uuid NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
  system_root text NOT NULL,
  status      text NOT NULL DEFAULT 'todo',   -- todo | doing | hold
  owner       text NOT NULL DEFAULT '',
  due_date    date,
  note        text NOT NULL DEFAULT '',
  updated_at  timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (host_id, system_root)
);
