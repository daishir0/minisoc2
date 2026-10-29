-- Running services reported by agents, with what they were linked to.
CREATE TABLE host_services (
  host_id      uuid NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
  name         text NOT NULL,
  cwd          text NOT NULL DEFAULT '',
  bin          text NOT NULL DEFAULT '',
  run_user     text NOT NULL DEFAULT '',
  system_root  text,   -- application the service belongs to
  runtime_root text,   -- shared runtime it uses (conda env ...)
  os_pkg       text,   -- OS package of its executable (nodejs24, python3.12, httpd ...)
  PRIMARY KEY (host_id, name)
);
