-- Rollback OIDC claims in ID token settings

ALTER TABLE clients
DROP COLUMN include_open_id_connect_claims_in_id_token;

ALTER TABLE settings
DROP COLUMN include_open_id_connect_claims_in_id_token;
