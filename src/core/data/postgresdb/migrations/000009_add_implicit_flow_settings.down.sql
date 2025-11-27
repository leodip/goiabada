-- Remove implicit flow settings
ALTER TABLE clients DROP COLUMN implicit_grant_enabled;
ALTER TABLE settings DROP COLUMN implicit_flow_enabled;
