-- Rollback PKCE configuration settings
ALTER TABLE settings DROP COLUMN pkce_required;
ALTER TABLE clients DROP COLUMN pkce_required;
