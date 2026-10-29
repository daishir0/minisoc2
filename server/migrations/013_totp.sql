-- Optional TOTP (RFC 6238) second factor for admin login. The secret is stored encrypted
-- (AES-256-GCM, same as other app secrets). totp_enabled is set only after a code is confirmed.
ALTER TABLE admin_users ADD COLUMN totp_secret  text    NOT NULL DEFAULT '';
ALTER TABLE admin_users ADD COLUMN totp_enabled boolean NOT NULL DEFAULT false;
