-- Migration 000078 down: drop a client's privacy policy and terms of service URLs, and every URL set
-- since with them. Each constraint before its column: see the up migration for why.
ALTER TABLE [clients] DROP CONSTRAINT [df_clients_terms_of_service_url];
ALTER TABLE [clients] DROP COLUMN [terms_of_service_url];
ALTER TABLE [clients] DROP CONSTRAINT [df_clients_privacy_policy_url];
ALTER TABLE [clients] DROP COLUMN [privacy_policy_url];
