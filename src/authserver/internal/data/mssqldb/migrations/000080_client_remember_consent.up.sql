-- A client's Remember consent setting (#711 decisions 1, 4 and 7). See the sqlite migration of the
-- same number for what the column means, why it defaults to off and why the backfill turns it on
-- for every confidential client alone.
--
-- The default constraint is NAMED so the down migration can drop it by name before the column,
-- for the reason 000029 gives.
ALTER TABLE [clients] ADD [remember_consent] BIT NOT NULL
    CONSTRAINT [df_clients_remember_consent] DEFAULT 0;

-- Inside EXEC because SQL Server compiles the whole batch before running any of it, so a statement
-- naming the column just added fails with "Invalid column name": see 000029.
EXEC('UPDATE [clients] SET [remember_consent] = 1 WHERE [is_public] = 0');
