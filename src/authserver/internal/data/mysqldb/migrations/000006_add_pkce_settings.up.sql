-- Add PKCE configuration settings
-- Global setting: defaults to TRUE (PKCE required) - recommended by OAuth 2.1
ALTER TABLE settings
ADD COLUMN pkce_required BOOLEAN NOT NULL DEFAULT TRUE;

-- Per-client override: NULL means use global setting
-- TRUE = PKCE required, FALSE = PKCE optional
ALTER TABLE clients
ADD COLUMN pkce_required BOOLEAN DEFAULT NULL;
