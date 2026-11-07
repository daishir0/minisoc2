-- Record what the change actually was (content hash before/after) on each daily file-integrity diff row,
-- so the UI can show "added / content changed (old -> new) / removed" from the received data.
ALTER TABLE host_file_day ADD COLUMN IF NOT EXISTS old_sha text;
ALTER TABLE host_file_day ADD COLUMN IF NOT EXISTS new_sha text;
