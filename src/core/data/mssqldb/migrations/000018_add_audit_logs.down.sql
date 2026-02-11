IF OBJECT_ID('audit_logs', 'U') IS NOT NULL DROP TABLE audit_logs;
ALTER TABLE settings DROP COLUMN audit_logs_in_console_enabled;
ALTER TABLE settings DROP COLUMN audit_logs_in_database_enabled;
ALTER TABLE settings DROP COLUMN audit_log_retention_days;
