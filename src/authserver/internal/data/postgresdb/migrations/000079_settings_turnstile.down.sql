-- Migration 000079 down: drop the three columns. See the sqlite migration for what a database migrated
-- forward again reads.
ALTER TABLE settings DROP COLUMN turnstile_secret_key_encrypted;

ALTER TABLE settings DROP COLUMN turnstile_site_key;

ALTER TABLE settings DROP COLUMN turnstile_enabled;
