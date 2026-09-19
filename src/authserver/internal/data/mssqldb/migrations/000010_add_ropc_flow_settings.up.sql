-- Resource Owner Password Credentials (ROPC) flow settings
-- RFC 6749 Section 4.3
-- SECURITY NOTE: ROPC is deprecated in OAuth 2.1 due to credential exposure risks.

-- Global setting to enable/disable ROPC flow server-wide
ALTER TABLE settings
ADD resource_owner_password_credentials_enabled BIT NOT NULL DEFAULT 0;

-- Per-client ROPC flow toggle
-- NULL = use global setting, 1 = enabled, 0 = disabled
ALTER TABLE clients
ADD resource_owner_password_credentials_enabled BIT DEFAULT NULL;
