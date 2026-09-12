DROP INDEX [idx_audit_logs_request_id] ON [audit_logs];

ALTER TABLE [audit_logs] DROP CONSTRAINT [df_audit_logs_request_id];

ALTER TABLE [audit_logs] DROP COLUMN [request_id];
