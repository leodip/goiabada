-- Constraint before column: see the up migration for why. consent_required keeps the
-- values the backfill set, also for the reason the up migration gives.
ALTER TABLE [clients] DROP CONSTRAINT [df_clients_created_via_dcr];
ALTER TABLE [clients] DROP COLUMN [created_via_dcr];
