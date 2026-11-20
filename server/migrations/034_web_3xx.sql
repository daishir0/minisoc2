-- Add a 3xx (redirect) counter to the per-vhost daily web aggregate. The summary surfaces 3xx / 4xx / 5xx
-- side by side; 2xx is derived as req - (c3xx + c4xx + c5xx). Forward-only: historical rows keep c3xx = 0.
ALTER TABLE web_daily ADD COLUMN IF NOT EXISTS c3xx bigint NOT NULL DEFAULT 0;
