-- Migration 000078 down: drop a client's privacy policy and terms of service URLs, and every URL set
-- since with them.
ALTER TABLE clients DROP COLUMN terms_of_service_url;
ALTER TABLE clients DROP COLUMN privacy_policy_url;
