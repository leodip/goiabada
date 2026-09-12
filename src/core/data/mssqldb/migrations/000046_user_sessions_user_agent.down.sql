-- The header is not recoverable once the column is gone: see the sqlite migration for why.
--
-- Constraint before column: see the up migration for why.
ALTER TABLE [user_sessions] DROP CONSTRAINT [df_user_sessions_user_agent];
ALTER TABLE [user_sessions] DROP COLUMN [user_agent];
