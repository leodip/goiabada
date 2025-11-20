-- Add Dynamic Client Registration settings (RFC 7591)
ALTER TABLE settings
ADD COLUMN dynamic_client_registration_enabled BOOLEAN NOT NULL DEFAULT 0;
