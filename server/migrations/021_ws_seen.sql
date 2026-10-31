-- Real-time control channel: when a host holds a live WebSocket, the hub stamps this on connect and
-- on every keepalive pong (~30s). Distinct from last_checkin_at (the 5-minute HTTP poll) so the
-- console can tell "connected right now" from "polled recently".
ALTER TABLE hosts ADD COLUMN IF NOT EXISTS ws_seen_at timestamptz;
