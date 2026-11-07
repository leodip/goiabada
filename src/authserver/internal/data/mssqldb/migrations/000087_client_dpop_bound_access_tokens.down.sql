-- Migration 000087 down: drop a client's "Require DPoP for token requests", and every setting made
-- since with it. Constraint before column: see the up migration for why.
ALTER TABLE [clients] DROP CONSTRAINT [df_clients_dpop_bound_access_tokens];
ALTER TABLE [clients] DROP COLUMN [dpop_bound_access_tokens];
