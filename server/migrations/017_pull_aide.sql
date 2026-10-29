-- Pull-type hosts: configurable file-integrity (AIDE) scan. aide_paths are directories to hash
-- read-only over SSH; aide_excludes are absolute sub-paths to skip. Empty aide_paths keeps the
-- default (SSH/cron files only). Hashes feed the same server-side baseline as agent hosts.
ALTER TABLE pull_targets ADD COLUMN aide_paths    text[] NOT NULL DEFAULT '{}';
ALTER TABLE pull_targets ADD COLUMN aide_excludes text[] NOT NULL DEFAULT '{}';
