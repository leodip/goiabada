-- One key per state (#251). See the sqlite migration of the same number for which
-- readers already assume it, why the sweep keeps the highest id per state, and why a
-- duplicate is swept rather than failing the migration.
--
-- No EXEC and no named default constraint here, unlike 000029 and 000026: this
-- migration adds no column, so nothing in the batch names an identifier the same
-- batch has just created, and there is no default for the down migration to drop
-- before the column.
DELETE FROM [key_pairs]
 WHERE [id] NOT IN (SELECT [id] FROM (SELECT MAX([id]) AS [id] FROM [key_pairs] GROUP BY [state]) AS keep);

CREATE UNIQUE INDEX [idx_key_pairs_state] ON [key_pairs]([state]);
