-- The DEFAULT constraints go before the columns they sit on. SQL Server refuses to drop a
-- column while a default constraint depends on it, and the up migration created these UNNAMED,
-- so each one carries a per-database generated name and can only be found through
-- sys.default_constraints. Without this the rollback fails at the first column and leaves the
-- schema half stepped down. The rule that every added default be named arrived with 000040;
-- these files predate it, and the fix belongs in the down rather than in a new migration
-- because a new migration would run at a different version (#268 decision 12).
-- The discovery is pinned to the exact object each DROP COLUMN below targets, through
-- OBJECT_ID, and never to a table NAME alone. sys.default_constraints spans the whole
-- database, so a name-only filter also matches a same-named table in any other schema the
-- operator has created, and the statement this builds is schema-qualified, so it would go
-- on to drop that table's defaults too (#268).
DECLARE @drop NVARCHAR(MAX) = N'';
SELECT @drop = @drop + N'ALTER TABLE ' + QUOTENAME(SCHEMA_NAME(t.schema_id)) + N'.' + QUOTENAME(t.name)
                     + N' DROP CONSTRAINT ' + QUOTENAME(dc.name) + N';'
FROM sys.default_constraints dc
JOIN sys.columns c ON c.object_id = dc.parent_object_id AND c.column_id = dc.parent_column_id
JOIN sys.tables t ON t.object_id = dc.parent_object_id
WHERE (dc.parent_object_id = OBJECT_ID(N'clients') AND c.name IN (N'website_url'));
EXEC sp_executesql @drop;

ALTER TABLE clients DROP COLUMN website_url;
