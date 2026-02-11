CREATE TABLE audit_logs (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    created_at DATETIME(6) NOT NULL,
    audit_event VARCHAR(128) NOT NULL,
    details TEXT NOT NULL,
    PRIMARY KEY (id),
    INDEX idx_audit_logs_created_at (created_at),
    INDEX idx_audit_logs_audit_event (audit_event)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

ALTER TABLE settings ADD COLUMN audit_logs_in_console_enabled BOOLEAN NOT NULL DEFAULT 1;
ALTER TABLE settings ADD COLUMN audit_logs_in_database_enabled BOOLEAN NOT NULL DEFAULT 1;
ALTER TABLE settings ADD COLUMN audit_log_retention_days INTEGER NOT NULL DEFAULT 180;
