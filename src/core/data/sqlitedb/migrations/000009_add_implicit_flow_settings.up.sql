-- Add implicit flow settings
-- Default is 0 (disabled) per OAuth 2.1 recommendation which deprecates implicit flow

-- Global setting to enable/disable implicit flow server-wide
ALTER TABLE settings
ADD COLUMN implicit_flow_enabled BOOLEAN NOT NULL DEFAULT 0;

-- Per-client implicit flow toggle
-- NULL = use global setting, 1 = enabled, 0 = disabled
ALTER TABLE clients
ADD COLUMN implicit_grant_enabled BOOLEAN DEFAULT NULL;
