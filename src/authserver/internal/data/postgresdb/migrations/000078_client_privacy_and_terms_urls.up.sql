-- A client's own privacy policy URL and terms of service URL (#622 decision 12). See the sqlite
-- migration of the same number for what the columns hold and why nothing is backfilled.
--
-- The width is website_url's, the URL they are validated like.
ALTER TABLE clients ADD COLUMN privacy_policy_url varchar(256) NOT NULL DEFAULT '';
ALTER TABLE clients ADD COLUMN terms_of_service_url varchar(256) NOT NULL DEFAULT '';
