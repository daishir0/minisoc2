-- Effective agent settings and run context reported by push agents, so the console can show what is
-- being monitored and generate ready-to-paste commands to change it (the server never commands hosts).
ALTER TABLE hosts ADD COLUMN agent_config jsonb;
ALTER TABLE hosts ADD COLUMN agent_meta   jsonb;
