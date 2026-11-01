-- Reverses migration 000074 (#631). Every user's page language is lost: each is back on Automatic,
-- and a database migrated forward again reads '' on every row.
ALTER TABLE users DROP COLUMN page_language;
