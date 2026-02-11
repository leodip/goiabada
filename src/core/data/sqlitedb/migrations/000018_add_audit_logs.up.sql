CREATE TABLE audit_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at DATETIME NOT NULL,
    audit_event TEXT NOT NULL,
    details TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX idx_audit_logs_created_at ON audit_logs(created_at);
CREATE INDEX idx_audit_logs_audit_event ON audit_logs(audit_event);

ALTER TABLE settings ADD COLUMN audit_logs_in_console_enabled BOOLEAN NOT NULL DEFAULT 1;
ALTER TABLE settings ADD COLUMN audit_logs_in_database_enabled BOOLEAN NOT NULL DEFAULT 1;
ALTER TABLE settings ADD COLUMN audit_log_retention_days INTEGER NOT NULL DEFAULT 180;
