-- Migration 000079 down: drop the three columns. A database migrated forward again has the challenge
-- off with no keys stored, whatever an administrator had set.
ALTER TABLE settings DROP COLUMN turnstile_secret_key_encrypted;

ALTER TABLE settings DROP COLUMN turnstile_site_key;

ALTER TABLE settings DROP COLUMN turnstile_enabled;
