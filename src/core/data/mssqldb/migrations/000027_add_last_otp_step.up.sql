-- Per-user one-time-use marker for TOTP codes (#111). See the sqlite migration of
-- the same number for what the column means and why existing rows land at 0.
--
-- The default constraint is NAMED deliberately. SQL Server refuses to drop a column
-- while a default constraint depends on it ("ALTER TABLE DROP COLUMN failed because
-- one or more objects access this column"), so the down migration has to drop the
-- constraint by name first. Naming it here is what makes that possible.
ALTER TABLE [users] ADD [last_otp_step] BIGINT NOT NULL
    CONSTRAINT [df_users_last_otp_step] DEFAULT 0;
