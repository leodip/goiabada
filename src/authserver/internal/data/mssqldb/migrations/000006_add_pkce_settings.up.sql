-- Add PKCE configuration settings
-- Global setting: defaults to 1 (PKCE required) - recommended by OAuth 2.1
ALTER TABLE [dbo].[settings]
ADD [pkce_required] BIT NOT NULL DEFAULT 1;

-- Per-client override: NULL means use global setting
-- 1 = PKCE required, 0 = PKCE optional
ALTER TABLE [dbo].[clients]
ADD [pkce_required] BIT DEFAULT NULL;
