-- Systems become first-class records: explicit (manual) registrations decide how packages are
-- grouped, and every system carries the attributes used for prioritising.
ALTER TABLE systems ADD COLUMN origin text NOT NULL DEFAULT 'auto';        -- auto | manual
ALTER TABLE systems ADD COLUMN exposure text NOT NULL DEFAULT 'unknown';   -- public | internal | dev | unknown
ALTER TABLE systems ADD COLUMN criticality text NOT NULL DEFAULT 'normal'; -- high | normal | low
ALTER TABLE systems ADD COLUMN url text NOT NULL DEFAULT '';
ALTER TABLE systems ADD COLUMN owner text NOT NULL DEFAULT '';
ALTER TABLE systems ADD COLUMN note text NOT NULL DEFAULT '';
ALTER TABLE systems ADD COLUMN stack text NOT NULL DEFAULT '';             -- set by hand; otherwise detected

-- explicit roots that were stored per host become manual systems
UPDATE systems s SET origin = 'manual'
FROM hosts h
WHERE h.id = s.host_id AND s.root = ANY(h.system_roots);
