-- Per-user authentication generation boundary (#106). See the sqlite migration of
-- the same number for what the columns mean and why existing rows land at 0.
--
-- The default constraints are NAMED deliberately. SQL Server refuses to drop a
-- column while a default constraint depends on it ("ALTER TABLE DROP COLUMN failed
-- because one or more objects access this column"), so the down migration has to drop
-- the constraint by name first. Naming them here is what makes that possible.
ALTER TABLE [users] ADD [auth_state_generation] BIGINT NOT NULL
    CONSTRAINT [df_users_auth_state_generation] DEFAULT 0;
ALTER TABLE [user_sessions] ADD [auth_state_generation] BIGINT NOT NULL
    CONSTRAINT [df_user_sessions_auth_state_generation] DEFAULT 0;
ALTER TABLE [codes] ADD [auth_state_generation] BIGINT NOT NULL
    CONSTRAINT [df_codes_auth_state_generation] DEFAULT 0;
ALTER TABLE [refresh_tokens] ADD [auth_state_generation] BIGINT NOT NULL
    CONSTRAINT [df_refresh_tokens_auth_state_generation] DEFAULT 0;

-- SQL Server does not index foreign key columns automatically. 000011 already added
-- idx_refresh_tokens_user_id, so refresh_tokens.user_id is covered and the rest are not.
CREATE INDEX [idx_codes_user_id] ON [codes]([user_id]);
CREATE INDEX [idx_codes_session_identifier] ON [codes]([session_identifier]);
CREATE INDEX [idx_refresh_tokens_code_id] ON [refresh_tokens]([code_id]);
CREATE INDEX [idx_user_sessions_user_id] ON [user_sessions]([user_id]);
