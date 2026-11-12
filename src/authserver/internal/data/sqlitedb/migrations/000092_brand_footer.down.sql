-- Reverses migration 000092 (#814): drops every brand's support contact and footer links.
ALTER TABLE brands DROP COLUMN footer_links;
ALTER TABLE brands DROP COLUMN support_phone;
ALTER TABLE brands DROP COLUMN support_url;
ALTER TABLE brands DROP COLUMN support_email;
