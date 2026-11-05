-- audit_logs rows record the user they are about and the user who acted (#780 decisions 1 and 2).
-- See the sqlite migration of the same number for what each column holds, why both are nullable
-- with no foreign key, and why each has an index of its own.
--
-- No DEFAULT, so no constraint to name; no collation, since neither column is a string.
ALTER TABLE [audit_logs] ADD [user_id] BIGINT NULL, [logged_in_user_id] BIGINT NULL;

CREATE INDEX [idx_audit_logs_user_id] ON [audit_logs]([user_id]);
CREATE INDEX [idx_audit_logs_logged_in_user_id] ON [audit_logs]([logged_in_user_id]);
