-- parity: mssql only. VARCHAR against NVARCHAR is a SQL Server distinction. MySQL, PostgreSQL
-- and SQLite each have a single string type and declared these five columns in it from the
-- start, so none of them has a conversion to carry.
--
-- Five columns were declared VARCHAR where every comparable column on this engine is
-- NVARCHAR (#282). Two of them, codes.code_challenge and codes.code_challenge_method,
-- are a regression: 000001 created them NVARCHAR and 000007 rewrote them as VARCHAR
-- while making them nullable. The other three arrived that way in 000008, 000013 and
-- 000014.
--
-- What this does and does not buy. NewMsSQLDatabase creates the database with
-- COLLATE Latin1_General_100_CI_AI_SC_UTF8, and under a UTF-8 collation VARCHAR stores
-- the full Unicode range losslessly, so a database Goiabada created was never losing
-- anything. The creation is IF NOT EXISTS, so an operator who pre-creates the database
-- gets the server's default collation instead, and on a stock SQL Server that is
-- SQL_Latin1_General_CP1_CI_AS, under which VARCHAR replaces anything outside the code
-- page with '?'. That loss is irreversible: a value already stored as 'café-é?' stays
-- 'café-é?' after this ALTER. So this stops future loss on a badly collated deployment
-- and repairs nothing.
--
-- EVERY ALTER COLUMN BELOW RESTATES ITS NULLABILITY, and that is not decoration.
-- ALTER TABLE ... ALTER COLUMN c <type> with no NULL or NOT NULL keyword makes the
-- column NULLABLE whatever it was before, so writing these without the keyword would
-- quietly drop NOT NULL from three columns while fixing their character set: one
-- divergence traded for another, and nothing in the tree would notice.
ALTER TABLE [codes] ALTER COLUMN [code_challenge] NVARCHAR(256) NULL;
ALTER TABLE [codes] ALTER COLUMN [code_challenge_method] NVARCHAR(10) NULL;
ALTER TABLE [user_profile_pictures] ALTER COLUMN [content_type] NVARCHAR(64) NOT NULL;
ALTER TABLE [client_logos] ALTER COLUMN [content_type] NVARCHAR(64) NOT NULL;

-- The fifth carries a default constraint, and SQL Server refuses ALTER COLUMN while one
-- depends on the column ("ERROR 4922 ... because one or more objects access this
-- column"). 000013 added it without a name, so SQL Server generated one, and the
-- generated name differs per database: DF__clients__include__37A5467C in the probe and
-- DF__clients__include__03F0984C in the dev container's goiabada_data. The name
-- therefore has to be read from the catalog at run time; a literal would work on
-- exactly one database.
--
-- The replacement is NAMED, for the reason 000024, 000026 and 000029 give: an unnamed
-- constraint cannot be dropped by a later migration without repeating this lookup.
DECLARE @df_name sysname = (
    SELECT dc.[name]
      FROM sys.default_constraints dc
      JOIN sys.columns c
        ON c.[object_id] = dc.[parent_object_id]
       AND c.[column_id] = dc.[parent_column_id]
     WHERE dc.[parent_object_id] = OBJECT_ID('dbo.clients')
       AND c.[name] = 'include_open_id_connect_claims_in_id_token');

EXEC('ALTER TABLE [clients] DROP CONSTRAINT [' + @df_name + ']');

ALTER TABLE [clients] ALTER COLUMN [include_open_id_connect_claims_in_id_token] NVARCHAR(10) NOT NULL;

ALTER TABLE [clients] ADD CONSTRAINT [df_clients_include_open_id_connect_claims_in_id_token]
    DEFAULT 'default' FOR [include_open_id_connect_claims_in_id_token];
