-- Which sessions were flagged is not restored: see the sqlite migration for why. The column comes
-- back with a NAMED default the original did not have, because existing rows need a value and
-- because the up migration has to be able to drop it by name on a re-apply.
ALTER TABLE [user_sessions] ADD [level2_auth_config_has_changed] BIT NOT NULL
    CONSTRAINT [df_user_sessions_level2_auth_config_has_changed] DEFAULT 0;

-- Constraints before columns: see the up migration for why.
ALTER TABLE [user_sessions] DROP CONSTRAINT [df_user_sessions_otp_config_generation];
ALTER TABLE [user_sessions] DROP COLUMN [otp_config_generation];
ALTER TABLE [users] DROP CONSTRAINT [df_users_otp_config_generation];
ALTER TABLE [users] DROP COLUMN [otp_config_generation];
