-- Add implicit flow settings
-- Default is FALSE (disabled) per OAuth 2.1 recommendation which deprecates implicit flow

-- Global setting to enable/disable implicit flow server-wide
ALTER TABLE settings
ADD COLUMN implicit_flow_enabled BOOLEAN NOT NULL DEFAULT FALSE;

-- Per-client implicit flow toggle
-- NULL = use global setting, TRUE = enabled, FALSE = disabled
ALTER TABLE clients
ADD COLUMN implicit_grant_enabled BOOLEAN DEFAULT NULL;
