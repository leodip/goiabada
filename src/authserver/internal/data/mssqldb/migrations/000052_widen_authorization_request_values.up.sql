-- parity: mysql, postgres and mssql only. SQLite stores all five columns as TEXT, which has no width.
--
-- Widens the five columns an authorization request's free-form values are stored in from 512 to
-- 2048 (#437): codes.state, codes.nonce, codes.scope, refresh_tokens.scope and
-- user_consents.scope. See the MySQL migration of the same number for why each, and why the three
-- scope columns move together.
--
-- The handlers bound all three values in bytes, and SQL Server counts an NVARCHAR's width in UTF-16
-- units, of which a string never has more than it has bytes, so a value they admit is never wider
-- than the column. 2048 keeps the columns on NVARCHAR(n), whose ceiling is 4000. ALTER COLUMN
-- replaces the column's definition, so the collation and NOT NULL are restated: with no NULL
-- keyword the column would become nullable, and with no COLLATE it would take the database default
-- (#283). None of the five carries a default constraint or is covered by an index.
--
-- ATOMIC, as 000040 and 000049 are: the runner hands a SQL Server file to one Exec and opens no
-- transaction, so without the pair below each ALTER autocommits and a failure on a later one
-- leaves the earlier ones applied and the version dirty. Wrapped, any failure rolls the file back
-- to the schema it started from, and clearing the dirty version and running it again completes it.
SET XACT_ABORT ON;
BEGIN TRANSACTION;

ALTER TABLE [codes] ALTER COLUMN [state] NVARCHAR(2048) COLLATE Latin1_General_100_CS_AS_KS_WS_SC_UTF8 NOT NULL;

ALTER TABLE [codes] ALTER COLUMN [nonce] NVARCHAR(2048) COLLATE Latin1_General_100_CS_AS_KS_WS_SC_UTF8 NOT NULL;

ALTER TABLE [codes] ALTER COLUMN [scope] NVARCHAR(2048) COLLATE Latin1_General_100_CS_AS_KS_WS_SC_UTF8 NOT NULL;

ALTER TABLE [refresh_tokens] ALTER COLUMN [scope] NVARCHAR(2048) COLLATE Latin1_General_100_CS_AS_KS_WS_SC_UTF8 NOT NULL;

ALTER TABLE [user_consents] ALTER COLUMN [scope] NVARCHAR(2048) COLLATE Latin1_General_100_CS_AS_KS_WS_SC_UTF8 NOT NULL;

COMMIT TRANSACTION;
SET XACT_ABORT OFF;
