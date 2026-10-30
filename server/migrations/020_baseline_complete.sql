-- The file-integrity baseline is "complete" once a non-truncated scan has arrived. Until then the
-- scan is still converging (an initial scan can hit its budget before reaching every path), so files
-- first seen during convergence are pre-existing, not real additions, and must not raise alerts.
ALTER TABLE hosts ADD COLUMN file_baseline_complete boolean NOT NULL DEFAULT false;
-- hosts whose baseline predates this change and have only non-truncated scans are effectively complete
UPDATE hosts SET file_baseline_complete = true WHERE file_baseline_at IS NOT NULL;
