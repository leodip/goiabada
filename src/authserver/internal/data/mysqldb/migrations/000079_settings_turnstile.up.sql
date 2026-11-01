-- The Cloudflare Turnstile challenge's settings (#642 decision 1). See the sqlite migration of the
-- same number for what the three columns hold, and why the switch and the site key carry a default.
--
-- No COLLATE clause: settings is declared utf8mb4_0900_as_cs and a column added without one
-- inherits the table's. The types are the SMTP switch's and password's.
ALTER TABLE `settings` ADD COLUMN `turnstile_enabled` tinyint(1) NOT NULL DEFAULT 0;

ALTER TABLE `settings` ADD COLUMN `turnstile_site_key` varchar(128) NOT NULL DEFAULT '';

ALTER TABLE `settings` ADD COLUMN `turnstile_secret_key_encrypted` longblob NULL;
