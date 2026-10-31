-- Reverses migration 000076 (#622). Every document applies to all apps again, and the selected
-- apps are lost. The column's default constraint goes first: SQL Server refuses to drop a column a
-- constraint still names.
DROP TABLE [legal_documents_clients];
ALTER TABLE [legal_documents] DROP CONSTRAINT [df_legal_documents_applies_to_all_apps];
ALTER TABLE [legal_documents] DROP COLUMN [applies_to_all_apps];
