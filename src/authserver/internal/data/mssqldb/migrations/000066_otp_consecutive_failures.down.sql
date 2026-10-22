-- Constraint before column: see the up migration for why.
ALTER TABLE [users] DROP CONSTRAINT [df_users_otp_consecutive_failures];
ALTER TABLE [users] DROP COLUMN [otp_consecutive_failures];