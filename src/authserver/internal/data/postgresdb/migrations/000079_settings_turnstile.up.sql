-- The Cloudflare Turnstile challenge's settings (#642 decision 1). See the sqlite migration of the
-- same number for what the three columns hold, and why the switch and the site key carry a default.
ALTER TABLE settings ADD COLUMN turnstile_enabled boolean NOT NULL DEFAULT false;

ALTER TABLE settings ADD COLUMN turnstile_site_key varchar(128) NOT NULL DEFAULT '';

ALTER TABLE settings ADD COLUMN turnstile_secret_key_encrypted bytea NULL;
