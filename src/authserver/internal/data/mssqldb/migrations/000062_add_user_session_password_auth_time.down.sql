-- The sessions the up migration ended are not restored.
ALTER TABLE [user_sessions] DROP COLUMN [password_auth_time];
