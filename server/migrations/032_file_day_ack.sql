-- Let an important file change be acknowledged ("確認済み"), the same way a log-threat alert can, so the
-- ファイル改ざん badge can be cleared once a change has been reviewed. The row stays for history; only the
-- badge / "要確認" surface filters on acked_at IS NULL.
ALTER TABLE host_file_day ADD COLUMN IF NOT EXISTS acked_at timestamptz;
