-- The token_endpoint_auth_method a client registered through dynamic client registration (#708
-- decision 3). See the sqlite migration of the same number for what the column holds and why
-- nothing is backfilled.
--
-- Latin1_General_100_CS_AS_KS_WS_SC_UTF8 is the case-, accent- and width-sensitive collation every
-- string column here carries since 000040. The default constraint is NAMED for the reason 000031
-- gives: SQL Server refuses to drop a column while a default constraint depends on it, so the down
-- migration drops the constraint by name first.
ALTER TABLE [clients] ADD [token_endpoint_auth_method] NVARCHAR(64) COLLATE Latin1_General_100_CS_AS_KS_WS_SC_UTF8 NOT NULL
    CONSTRAINT [df_clients_token_endpoint_auth_method] DEFAULT '';
