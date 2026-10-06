-- Migration 000060 down: drop clients.administrative_scopes_allowed. Every allowance an operator
-- switched on goes with it; the previous release reads no such column and refuses no client.
ALTER TABLE clients DROP COLUMN administrative_scopes_allowed;
