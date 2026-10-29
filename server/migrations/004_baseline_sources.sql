-- Finding sources (osv, os-advisory) whose first appearance on a host was already taken as a baseline.
ALTER TABLE hosts ADD COLUMN baseline_sources text[] NOT NULL DEFAULT '{}';
UPDATE hosts h SET baseline_sources = COALESCE((SELECT array_agg(DISTINCT source) FROM findings f WHERE f.host_id = h.id), '{}')
WHERE h.baseline_done;
