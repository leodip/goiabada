-- Rollback ROPC flow settings

ALTER TABLE clients
DROP COLUMN resource_owner_password_credentials_enabled;

ALTER TABLE settings
DROP COLUMN resource_owner_password_credentials_enabled;
