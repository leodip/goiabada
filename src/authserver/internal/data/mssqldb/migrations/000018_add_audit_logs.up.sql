CREATE TABLE audit_logs (
    id BIGINT IDENTITY(1,1) PRIMARY KEY,
    created_at DATETIME2(6) NOT NULL,
    audit_event NVARCHAR(128) NOT NULL,
    details NVARCHAR(MAX) NOT NULL DEFAULT '{}'
);
CREATE INDEX idx_audit_logs_created_at ON audit_logs(created_at);
CREATE INDEX idx_audit_logs_audit_event ON audit_logs(audit_event);

ALTER TABLE settings ADD audit_logs_in_console_enabled BIT NOT NULL DEFAULT 1;
ALTER TABLE settings ADD audit_logs_in_database_enabled BIT NOT NULL DEFAULT 1;
ALTER TABLE settings ADD audit_log_retention_days INT NOT NULL DEFAULT 180;
