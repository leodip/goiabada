-- Reverses migration 000092 (#814). See the sqlite migration for what is lost.
ALTER TABLE brands DROP COLUMN footer_links;
ALTER TABLE brands DROP COLUMN support_phone;
ALTER TABLE brands DROP COLUMN support_url;
ALTER TABLE brands DROP COLUMN support_email;
