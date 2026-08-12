-- Self-registered clients require consent (#108). See the sqlite migration of the same
-- number for what the column means, why the backfill also sets consent_required, and
-- why the escape character is '!' rather than '\'.
--
-- The default constraint is NAMED deliberately, for the reason 000024 and 000026 give:
-- SQL Server refuses to drop a column while a default constraint depends on it, so the
-- down migration has to drop the constraint by name first.
ALTER TABLE [clients] ADD [created_via_dcr] BIT NOT NULL
    CONSTRAINT [df_clients_created_via_dcr] DEFAULT 0;

-- The backfill runs inside EXEC, which no other engine needs. SQL Server compiles an
-- entire batch before executing any of it, so a statement naming a column the same
-- batch has just added fails at compile time with "Invalid column name", before the
-- ALTER above has run. EXEC defers name resolution to a batch of its own. The usual
-- separator would be GO, but that is a client-tool directive rather than T-SQL and
-- golang-migrate sends each migration file to the driver as one statement, so EXEC is
-- the separator available here. Single quotes are doubled because the whole UPDATE is
-- now a string literal.
EXEC('UPDATE [clients] SET [created_via_dcr] = 1, [consent_required] = 1
 WHERE [client_identifier] LIKE ''dcr!_%'' ESCAPE ''!''');
