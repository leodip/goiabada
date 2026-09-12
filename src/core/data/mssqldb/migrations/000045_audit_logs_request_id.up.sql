-- audit_logs rows carry the request id of the request that raised the event (#328). See the
-- sqlite migration of the same number for what the column holds, why the client-chosen value
-- is safe to store at this width, and why the index lands here with no reader yet.
--
-- The collation is spelled per column because NewMsSQLDatabase creates the database IF NOT
-- EXISTS, so a database an operator pre-created keeps their own default, which on a stock
-- server folds case. The filter the next stage adds compares this column with =.
--
-- The DEFAULT constraint is named because SQL Server generates a per-database name otherwise,
-- and the down below drops it by name.
ALTER TABLE [audit_logs]
    ADD [request_id] NVARCHAR(256) COLLATE Latin1_General_100_CS_AS_KS_WS_SC_UTF8 NOT NULL
        CONSTRAINT [df_audit_logs_request_id] DEFAULT '';

CREATE INDEX [idx_audit_logs_request_id] ON [audit_logs]([request_id]);
