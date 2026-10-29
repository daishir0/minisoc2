-- Systems: the applications on a host (one per project directory), derived from lockfile paths.
CREATE TABLE systems (
  id         serial PRIMARY KEY,
  host_id    uuid NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
  root       text NOT NULL,           -- project directory, or '__os__' for OS packages
  name       text NOT NULL,
  ignored    boolean NOT NULL DEFAULT false,
  first_seen timestamptz NOT NULL DEFAULT now(),
  last_seen  timestamptz NOT NULL DEFAULT now(),
  UNIQUE (host_id, root)
);

-- extra system roots per host: "/srv/apps/*" makes each child directory a system
ALTER TABLE hosts ADD COLUMN system_roots text[] NOT NULL DEFAULT '{}';
ALTER TABLE host_packages ADD COLUMN systems text[] NOT NULL DEFAULT '{}';
ALTER TABLE findings ADD COLUMN systems text[] NOT NULL DEFAULT '{}';
CREATE INDEX findings_systems ON findings USING gin (systems);
