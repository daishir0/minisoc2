-- Config push: the console writes the desired agent config here; the control-channel hub delivers it
-- to the host (live, or on its next reconnect while config_pending). The agent applies the allowed
-- fields and reports back, which clears the pending flag. agent_config stays the REPORTED (actual) one.
ALTER TABLE hosts ADD COLUMN IF NOT EXISTS desired_config jsonb;
ALTER TABLE hosts ADD COLUMN IF NOT EXISTS config_pending boolean NOT NULL DEFAULT false;
