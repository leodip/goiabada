-- Migration 000080 down: drop clients.remember_consent, with every setting an administrator turned
-- on since. Constraint before column: see the up migration for why.
ALTER TABLE [clients] DROP CONSTRAINT [df_clients_remember_consent];
ALTER TABLE [clients] DROP COLUMN [remember_consent];
