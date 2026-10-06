-- A client's allowance to request the administrative authserver scopes (#499 decisions 3 and 8).
-- See the sqlite migration of the same number for what the column means and why the backfill
-- allows the admin console's client and no other.
--
-- The default constraint is NAMED so the down migration can drop it by name before the column,
-- for the reason 000029 gives.
ALTER TABLE [clients] ADD [administrative_scopes_allowed] BIT NOT NULL
    CONSTRAINT [df_clients_administrative_scopes_allowed] DEFAULT 0;

-- Inside EXEC because SQL Server compiles the whole batch before running any of it, so a
-- statement naming the column just added fails with "Invalid column name": see 000029. Single
-- quotes are doubled inside the string literal.
EXEC('UPDATE [clients] SET [administrative_scopes_allowed] = 1
 WHERE [client_identifier] = ''admin-console-client''');
