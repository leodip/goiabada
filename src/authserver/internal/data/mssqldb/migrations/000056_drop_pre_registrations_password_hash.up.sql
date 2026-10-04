-- Drop pre_registrations.password_hash (#207 decision 2). See the sqlite migration of the same
-- number for why nothing writes or reads the column any more, and which Go code goes with it.
--
-- The column is in no index and carries no DEFAULT constraint on this engine, so nothing has to
-- be dropped by name before it. The down migration drops the one it adds, so a roll back and a
-- retry find the column in the same state.
--
-- No EXEC wrapper, on 000033's reasoning: this adds no column and names only a column that already
-- exists, so a plain statement resolves at batch compile time.
ALTER TABLE [pre_registrations] DROP COLUMN [password_hash];
