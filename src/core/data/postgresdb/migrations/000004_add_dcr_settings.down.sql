-- Rollback Dynamic Client Registration settings
ALTER TABLE settings
DROP COLUMN dynamic_client_registration_enabled;
