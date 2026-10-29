-- A system that appears for the first time (new project, newly scanned Python env) is a baseline:
-- its existing findings are summarised once instead of alerting one by one.
ALTER TABLE systems ADD COLUMN baselined boolean NOT NULL DEFAULT false;
UPDATE systems SET baselined = true;
