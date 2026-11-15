-- Migration 000096 down: drop the token_endpoint_auth_method clients registered, and every method
-- stored since with it. Constraint before column: see the up migration for why.
ALTER TABLE [clients] DROP CONSTRAINT [df_clients_token_endpoint_auth_method];
ALTER TABLE [clients] DROP COLUMN [token_endpoint_auth_method];
