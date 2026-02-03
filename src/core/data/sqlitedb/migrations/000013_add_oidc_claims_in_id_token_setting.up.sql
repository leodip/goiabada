-- Add setting to control inclusion of OpenID Connect scope claims in ID tokens
-- Per OIDC Core 5.4, scope claims (email, profile, etc.) MAY be in ID tokens
-- but SHOULD be available from /userinfo endpoint for strict conformance.
-- Default is TRUE (enabled) to match industry standard behavior (Auth0, Microsoft, Keycloak).

-- Global setting to control OIDC claims in ID tokens server-wide
ALTER TABLE settings
ADD COLUMN include_open_id_connect_claims_in_id_token INTEGER NOT NULL DEFAULT 1;

-- Per-client override for OIDC claims in ID tokens
-- 'default' = use global setting, 'on' = enabled, 'off' = disabled
ALTER TABLE clients
ADD COLUMN include_open_id_connect_claims_in_id_token VARCHAR(10) NOT NULL DEFAULT 'default';
