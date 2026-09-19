-- audit_logs rows carry the request id of the request that raised the event (#328).
--
-- What it holds: the request id rendered exactly as core/logging renders the request_id
-- attribute on the application log, which is logging.FieldForLog of chi's id. That equality
-- is the whole point of the column: an administrator reading an event in the viewer takes the
-- value shown and greps the log for it, and the two have to be the same string byte for byte,
-- clipping and escaping included.
--
-- Why the value is safe to store. chi's RequestID middleware adopts an inbound X-Request-Id
-- header verbatim, so this is client-chosen, bounded only by the server's 1 MiB header cap.
-- FieldForLog percent-escapes every non-printable byte and clips at 128 with a counted marker,
-- so what reaches this column is printable ASCII of at most 161 bytes whatever was sent.
-- Width 256 leaves room above that bound without inviting a wider client-chosen value in.
--
-- NOT NULL DEFAULT '' rather than nullable: every row written before this migration, and the
-- startup email backfill's row, mean "not written on a request", and the empty string says that
-- in a table that carries no nullable string column today. The JSON layer would render a NULL
-- as "" anyway.
--
-- The index has no reader yet: the filter that uses it lands with the admin API's requestId
-- parameter in the next stage of this change. It is created here because the column and the
-- index are one schema decision and splitting them across two migration numbers would leave a
-- deployment that stopped between them with a filter and no index.
ALTER TABLE audit_logs ADD COLUMN request_id TEXT NOT NULL DEFAULT '';

CREATE INDEX idx_audit_logs_request_id ON audit_logs(request_id);
