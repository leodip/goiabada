-- The sessions the up migration ended are not restored, and the codes it revoked stay revoked.
ALTER TABLE [user_sessions] DROP COLUMN [password_auth_time];
