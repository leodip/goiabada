-- Migration 000060 down: drop clients.administrative_scopes_allowed, with every allowance an
-- operator switched on since. Constraint before column: see the up migration for why.
ALTER TABLE [clients] DROP CONSTRAINT [df_clients_administrative_scopes_allowed];
ALTER TABLE [clients] DROP COLUMN [administrative_scopes_allowed];
