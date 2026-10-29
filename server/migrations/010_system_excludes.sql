-- Paths inside a system that are intentionally vulnerable (test corpora, sample apps) and must not
-- count against it. Excluded packages are kept separately so they stay visible (counts, SBOM).
CREATE TABLE system_excludes (
  id          serial PRIMARY KEY,
  system_id   int NOT NULL REFERENCES systems(id) ON DELETE CASCADE,
  pattern     text NOT NULL,          -- relative to the system root: data/**, research/**/corpus*/**
  reason      text NOT NULL,
  created_by  text NOT NULL,
  created_at  timestamptz NOT NULL DEFAULT now(),
  review_date date,
  UNIQUE (system_id, pattern)
);

CREATE TABLE host_packages_excluded (
  host_id     uuid NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
  system_root text NOT NULL,
  pattern     text NOT NULL,
  ecosystem   text NOT NULL,
  name        text NOT NULL,
  version     text NOT NULL,
  PRIMARY KEY (host_id, system_root, pattern, ecosystem, name, version)
);
