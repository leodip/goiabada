-- Constraint before column: see the up migration for why.
ALTER TABLE [users] DROP CONSTRAINT [df_users_last_otp_step];
ALTER TABLE [users] DROP COLUMN [last_otp_step];
