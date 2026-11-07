-- A client's "Require DPoP for token requests" (#42 decision 12). See the sqlite migration of the
-- same number for what the column holds and why nothing is backfilled.
--
-- The default constraint is NAMED for the reason 000031 gives: SQL Server refuses to drop a column
-- while a default constraint depends on it, so the down migration drops the constraint by name
-- first.
ALTER TABLE [clients] ADD [dpop_bound_access_tokens] BIT NOT NULL
    CONSTRAINT [df_clients_dpop_bound_access_tokens] DEFAULT 0;
