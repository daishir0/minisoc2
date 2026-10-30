-- On-demand collection without an inbound channel: the console sets collect_requested, and the agent
-- picks it up on its frequent lightweight check-in (GET /api/v1/pending), then runs a full report.
-- last_checkin_at records the most recent check-in so the console can show responsiveness.
ALTER TABLE hosts ADD COLUMN collect_requested boolean NOT NULL DEFAULT false;
ALTER TABLE hosts ADD COLUMN last_checkin_at    timestamptz;
