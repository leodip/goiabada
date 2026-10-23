-- parity: mysql, postgres and mssql only. SQLite stores all four columns as TEXT, which has no width.
--
-- Widens the four columns an email address is stored in from 64 to 254 characters (#632):
-- users.email, pre_registrations.email, settings.smtp_from_email and settings.smtp_username. See
-- the MySQL migration of the same number for why each column, and why 254.
--
-- The address rule admits ASCII only, so its characters are its UTF-16 units and 254 of them fit
-- 254 wide. ALTER COLUMN replaces the column's definition, so the collation and NULL are
-- restated: with no COLLATE the column would take the database default (#283). SQL Server widens a
-- variable-length column in place under a non-primary-key index when the type and collation are
-- unchanged, as 000049 relies on, so idx_email and idx_pre_reg_email stay; the widened key of each
-- is 508 bytes, inside the 1700 a nonclustered index allows.
--
-- ATOMIC, as 000040, 000049 and 000052 are: the runner hands a SQL Server file to one Exec and
-- opens no transaction, so without the pair below each ALTER autocommits and a failure on a later
-- one leaves the earlier ones applied and the version dirty. Wrapped, any failure rolls the file
-- back to the schema it started from, and clearing the dirty version and running it again
-- completes it.
SET XACT_ABORT ON;
BEGIN TRANSACTION;

ALTER TABLE [users] ALTER COLUMN [email] NVARCHAR(254) COLLATE Latin1_General_100_CS_AS_KS_WS_SC_UTF8 NULL;

ALTER TABLE [pre_registrations] ALTER COLUMN [email] NVARCHAR(254) COLLATE Latin1_General_100_CS_AS_KS_WS_SC_UTF8 NULL;

ALTER TABLE [settings] ALTER COLUMN [smtp_from_email] NVARCHAR(254) COLLATE Latin1_General_100_CS_AS_KS_WS_SC_UTF8 NULL;

ALTER TABLE [settings] ALTER COLUMN [smtp_username] NVARCHAR(254) COLLATE Latin1_General_100_CS_AS_KS_WS_SC_UTF8 NULL;

COMMIT TRANSACTION;
SET XACT_ABORT OFF;
