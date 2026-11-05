-- Migration 000082 down: drop the indexes, then the columns, which SQL Server refuses while an
-- index names them. See the sqlite migration for what is lost.
DROP INDEX [idx_audit_logs_logged_in_user_id] ON [audit_logs];
DROP INDEX [idx_audit_logs_user_id] ON [audit_logs];

ALTER TABLE [audit_logs] DROP COLUMN [logged_in_user_id], [user_id];
