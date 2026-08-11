-- Look up a reset or activation link by an unsalted SHA-256 of its code (#112). See the
-- sqlite migration of the same number for what the columns mean, why one index is plain
-- and the other UNIQUE, and why the DELETE below makes this migration irreversible.
--
-- The default constraints are NAMED deliberately. SQL Server refuses to drop a column
-- while a default constraint depends on it ("ALTER TABLE DROP COLUMN failed because one
-- or more objects access this column"), so the down migration has to drop the constraint
-- by name first. Naming them here is what makes that possible.
DELETE FROM [pre_registrations];

ALTER TABLE [users] ADD [forgot_password_code_hash] NVARCHAR(64) NOT NULL
    CONSTRAINT [df_users_forgot_password_code_hash] DEFAULT '';
ALTER TABLE [pre_registrations] ADD [verification_code_hash] NVARCHAR(64) NOT NULL
    CONSTRAINT [df_pre_registrations_verification_code_hash] DEFAULT '';

-- Indexing a column added earlier in the same file is accepted here: golang-migrate sends
-- the file as one batch, and SQL Server resolves these names after the ALTER TABLE
-- statements have run rather than when the batch is parsed. Executed against SQL Server
-- 2022 through the 000028 migration test, so no dynamic-SQL wrapper is needed.
CREATE INDEX [idx_users_forgot_password_code_hash]
    ON [users]([forgot_password_code_hash]);
CREATE UNIQUE INDEX [idx_pre_reg_verification_code_hash]
    ON [pre_registrations]([verification_code_hash]);
