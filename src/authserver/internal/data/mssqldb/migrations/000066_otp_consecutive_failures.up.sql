-- Per-user count of consecutive failed attempts against the enrolled authenticator
-- (#489). See the sqlite migration of the same number for what the column means and
-- why existing rows land at 0.
--
-- The default constraint is NAMED deliberately, for last_otp_step's reason: SQL Server
-- refuses to drop a column while a default constraint depends on it, so the down
-- migration has to drop the constraint by name first. Naming it here is what makes that
-- possible.
ALTER TABLE [users] ADD [otp_consecutive_failures] BIGINT NOT NULL
    CONSTRAINT [df_users_otp_consecutive_failures] DEFAULT 0;