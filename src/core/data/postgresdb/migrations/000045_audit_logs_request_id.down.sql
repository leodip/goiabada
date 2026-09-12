DROP INDEX idx_audit_logs_request_id;

ALTER TABLE audit_logs DROP COLUMN request_id;
