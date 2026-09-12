-- audit_logs rows carry the request id of the request that raised the event (#328). See the
-- sqlite migration of the same number for what the column holds, why the client-chosen value
-- is safe to store at this width, and why the index lands here with no reader yet.
--
-- No collation pin: PostgreSQL compares byte-wise already.
ALTER TABLE audit_logs ADD COLUMN request_id character varying(256) NOT NULL DEFAULT '';

CREATE INDEX idx_audit_logs_request_id ON audit_logs(request_id);
