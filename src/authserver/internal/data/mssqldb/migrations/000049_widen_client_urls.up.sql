-- parity: mysql, postgres and mssql only. SQLite stores all three columns as TEXT, which has no width.
--
-- Widens the three columns a client's URLs are stored in to the bounds the handlers now enforce
-- (#428): redirect_uris.uri and codes.redirect_uri to 2048, web_origins.origin to 267. See the
-- MySQL migration of the same number for why each number, and why codes.redirect_uri moves with
-- redirect_uris.uri.
--
-- The handlers bound all three in bytes, and SQL Server counts an NVARCHAR's width in UTF-16
-- units, of which a string never has more than it has bytes, so a value they admit is never wider
-- than the column. 2048 keeps the redirect URI columns on NVARCHAR(n), whose ceiling is 4000.
-- ALTER COLUMN replaces the column's definition, so the collation and NOT NULL are restated: with
-- no NULL keyword the column would become nullable, and with no COLLATE it would take the
-- database default (#283). SQL Server widens a variable-length column in place under a
-- non-primary-key index when the type and collation are unchanged, so idx_web_origins_origin_client
-- stays; its widened key is 542 bytes, inside the 1700 a nonclustered index allows.
--
-- ATOMIC, as 000040 is: the runner hands a SQL Server file to one Exec and opens no transaction,
-- so without the pair below each ALTER autocommits and a failure on the second or third leaves the
-- first applied and the version dirty. Wrapped, any failure rolls the file back to the schema it
-- started from, and clearing the dirty version and running it again completes it.
SET XACT_ABORT ON;
BEGIN TRANSACTION;

ALTER TABLE [redirect_uris] ALTER COLUMN [uri] NVARCHAR(2048) COLLATE Latin1_General_100_CS_AS_KS_WS_SC_UTF8 NOT NULL;

ALTER TABLE [codes] ALTER COLUMN [redirect_uri] NVARCHAR(2048) COLLATE Latin1_General_100_CS_AS_KS_WS_SC_UTF8 NOT NULL;

ALTER TABLE [web_origins] ALTER COLUMN [origin] NVARCHAR(267) COLLATE Latin1_General_100_CS_AS_KS_WS_SC_UTF8 NOT NULL;

COMMIT TRANSACTION;
SET XACT_ABORT OFF;
