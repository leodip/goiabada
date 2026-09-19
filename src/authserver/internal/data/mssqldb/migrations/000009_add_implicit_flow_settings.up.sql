-- Add implicit flow settings
-- Default is 0 (disabled) per OAuth 2.1 recommendation which deprecates implicit flow

-- Global setting to enable/disable implicit flow server-wide
ALTER TABLE [dbo].[settings]
ADD [implicit_flow_enabled] BIT NOT NULL DEFAULT 0;

-- Per-client implicit flow toggle
-- NULL = use global setting, 1 = enabled, 0 = disabled
ALTER TABLE [dbo].[clients]
ADD [implicit_grant_enabled] BIT DEFAULT NULL;
