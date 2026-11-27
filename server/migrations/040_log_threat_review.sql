-- "Benign confirmed" verdicts for recurring log threats (the log-threat equivalent of a finding's VEX).
-- A reviewed topic (e.g. a vhost's scanner-recon spike) is downgraded to digest-only on recurrence so the
-- same benign sweep does not re-alert loudly every day. topic is a stable signature, e.g. 'web:<vhost>:recon'.
CREATE TABLE IF NOT EXISTS log_threat_review (
  host_id     uuid NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
  topic       text NOT NULL,
  note        text NOT NULL DEFAULT '',
  reviewed_by text NOT NULL DEFAULT '',
  reviewed_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (host_id, topic)
);
