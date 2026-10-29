-- Pull-type hosts: the server reaches them over read-only SSH (shared hosting with no agent, e.g.
-- Sakura rental server: no root, so OS package managers are usually absent; value comes from
-- lockfile SBOM, runtime versions and the user's logs). Credentials are stored encrypted.
ALTER TABLE hosts ADD COLUMN kind text NOT NULL DEFAULT 'push';  -- push | pull

CREATE TABLE pull_targets (
  host_id     uuid PRIMARY KEY REFERENCES hosts(id) ON DELETE CASCADE,
  ssh_host    text NOT NULL,
  ssh_port    int  NOT NULL DEFAULT 22,
  ssh_user    text NOT NULL,
  auth        text NOT NULL,                       -- 'key' | 'password'
  secret_enc  text NOT NULL,                        -- encrypted private key (PEM) or password
  scan_paths  text[] NOT NULL DEFAULT '{}',         -- dirs searched for lockfiles
  log_globs   text[] NOT NULL DEFAULT '{}',         -- log files to read (daily files ok)
  every_hours int NOT NULL DEFAULT 1,
  log_state   jsonb NOT NULL DEFAULT '{}'::jsonb,   -- path -> last size (incremental reads)
  last_poll_at timestamptz,
  last_error  text
);
