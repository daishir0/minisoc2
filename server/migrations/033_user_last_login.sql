-- Multi-user: admin_users already supports many rows (sessions and TOTP are per-user). Add last_login_at
-- so the user-management list can show when each account was last used; set on every session start.
ALTER TABLE admin_users ADD COLUMN IF NOT EXISTS last_login_at timestamptz;
