-- Which sessions were flagged is not restored: see the sqlite migration for why.
--
-- The default is NAMED so that it can be dropped again on the next line. SQL Server will not add
-- a NOT NULL column to a populated table without one, and 000001 declares this column BIT NOT
-- NULL with NO default, so leaving the constraint behind would restore a column that merely
-- resembles the one 000001 built: a database rolled back to 000030 would carry a default a fresh
-- install of that release does not have (#268 decision 12).
ALTER TABLE [user_sessions] ADD [level2_auth_config_has_changed] BIT NOT NULL
    CONSTRAINT [df_user_sessions_level2_auth_config_has_changed] DEFAULT 0;
ALTER TABLE [user_sessions] DROP CONSTRAINT [df_user_sessions_level2_auth_config_has_changed];

-- Constraints before columns: see the up migration for why.
ALTER TABLE [user_sessions] DROP CONSTRAINT [df_user_sessions_otp_config_generation];
ALTER TABLE [user_sessions] DROP COLUMN [otp_config_generation];
ALTER TABLE [users] DROP CONSTRAINT [df_users_otp_config_generation];
ALTER TABLE [users] DROP COLUMN [otp_config_generation];
