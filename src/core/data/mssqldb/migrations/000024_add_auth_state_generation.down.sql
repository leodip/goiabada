DROP INDEX [idx_user_sessions_user_id] ON [user_sessions];
DROP INDEX [idx_refresh_tokens_code_id] ON [refresh_tokens];
DROP INDEX [idx_codes_session_identifier] ON [codes];
DROP INDEX [idx_codes_user_id] ON [codes];

-- Constraints before columns: see the up migration for why.
ALTER TABLE [refresh_tokens] DROP CONSTRAINT [df_refresh_tokens_auth_state_generation];
ALTER TABLE [refresh_tokens] DROP COLUMN [auth_state_generation];
ALTER TABLE [codes] DROP CONSTRAINT [df_codes_auth_state_generation];
ALTER TABLE [codes] DROP COLUMN [auth_state_generation];
ALTER TABLE [user_sessions] DROP CONSTRAINT [df_user_sessions_auth_state_generation];
ALTER TABLE [user_sessions] DROP COLUMN [auth_state_generation];
ALTER TABLE [users] DROP CONSTRAINT [df_users_auth_state_generation];
ALTER TABLE [users] DROP COLUMN [auth_state_generation];
