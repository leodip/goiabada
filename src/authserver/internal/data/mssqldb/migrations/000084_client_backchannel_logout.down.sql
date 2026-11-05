-- Migration 000084 down: drop a client's back-channel logout settings, and every one set since with
-- them. Each constraint before its column: see the up migration for why.
ALTER TABLE [clients] DROP CONSTRAINT [df_clients_backchannel_logout_session_required];
ALTER TABLE [clients] DROP COLUMN [backchannel_logout_session_required];
ALTER TABLE [clients] DROP CONSTRAINT [df_clients_backchannel_logout_uri];
ALTER TABLE [clients] DROP COLUMN [backchannel_logout_uri];
