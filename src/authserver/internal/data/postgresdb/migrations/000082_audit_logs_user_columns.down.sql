-- Migration 000082 down: drop the indexes, then the columns. See the sqlite migration for what is
-- lost.
DROP INDEX idx_audit_logs_logged_in_user_id;
DROP INDEX idx_audit_logs_user_id;

ALTER TABLE audit_logs DROP COLUMN logged_in_user_id;
ALTER TABLE audit_logs DROP COLUMN user_id;
