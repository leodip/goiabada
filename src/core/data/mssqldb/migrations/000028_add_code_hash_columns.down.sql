-- NOT a true inverse: the up migration deletes every pre_registrations row and nothing
-- here can bring them back (#112). See the sqlite migration of the same number.
--
-- Indexes, then default constraints, then columns: SQL Server refuses to drop a column
-- while either still depends on it. See the up migration for why the constraints are
-- named.
DROP INDEX [idx_users_forgot_password_code_hash] ON [users];
DROP INDEX [idx_pre_reg_verification_code_hash] ON [pre_registrations];

ALTER TABLE [users] DROP CONSTRAINT [df_users_forgot_password_code_hash];
ALTER TABLE [pre_registrations] DROP CONSTRAINT [df_pre_registrations_verification_code_hash];

ALTER TABLE [users] DROP COLUMN [forgot_password_code_hash];
ALTER TABLE [pre_registrations] DROP COLUMN [verification_code_hash];
