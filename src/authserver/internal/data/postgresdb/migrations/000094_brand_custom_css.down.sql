-- Reverses migration 000094 (#816). See the sqlite migration for what is lost.
ALTER TABLE brands DROP COLUMN custom_css;
