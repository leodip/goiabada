-- The Cloudflare Turnstile challenge's settings (#642 decision 1): one switch for the sign-in,
-- forgot-password and registration forms, the widget's site key, and its secret key, sealed under
-- the data key as smtp_password_encrypted is and re-encrypted with it by a data-key rotation.
--
-- The switch defaults to off and the site key to empty, so an upgrade changes nothing until an
-- administrator turns the challenge on, and a rolling upgrade rests on it: the previous release,
-- still serving while this one migrates, saves settings naming none of the three columns, which
-- leaves them as stored. The secret key is nullable with no default, as the SMTP password is: no
-- secret key is stored until one is entered.
ALTER TABLE settings ADD COLUMN turnstile_enabled BOOLEAN NOT NULL DEFAULT 0;

ALTER TABLE settings ADD COLUMN turnstile_site_key TEXT NOT NULL DEFAULT '';

ALTER TABLE settings ADD COLUMN turnstile_secret_key_encrypted BLOB NULL;
