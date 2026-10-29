-- Sigma (SigmaHQ) log detection rules, synced from upstream and compiled to line matchers.
-- Only rules whose detection reduces to keyword/substring groups are kept (raw syslog lines have no
-- structured fields); the rest are skipped at sync time. "needles" is an AND-of-ORs matcher:
-- the line matches when every group has at least one of its (lowercased) substrings present.
CREATE TABLE sigma_rules (
  id         text PRIMARY KEY,          -- "sigma:<sigma-uuid>"
  title      text NOT NULL,
  level      text NOT NULL,             -- critical | high | medium | low | informational
  source_re  text NOT NULL DEFAULT '',  -- optional regex on the log source ("" = any)
  needles    jsonb NOT NULL,            -- string[][] (AND of ORs), all lowercase
  reference  text NOT NULL DEFAULT '',
  enabled    boolean NOT NULL DEFAULT true,
  updated_at timestamptz NOT NULL DEFAULT now()
);
