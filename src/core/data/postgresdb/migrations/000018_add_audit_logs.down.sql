DROP TABLE IF EXISTS audit_logs;
ALTER TABLE settings DROP COLUMN audit_logs_in_console_enabled;
ALTER TABLE settings DROP COLUMN audit_logs_in_database_enabled;
ALTER TABLE settings DROP COLUMN audit_log_retention_days;
