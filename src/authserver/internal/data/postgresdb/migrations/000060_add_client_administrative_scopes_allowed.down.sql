-- Migration 000060 down: drop clients.administrative_scopes_allowed, with every allowance an
-- operator switched on since.
ALTER TABLE clients DROP COLUMN administrative_scopes_allowed;
