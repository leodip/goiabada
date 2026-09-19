-- The http_sessions table backed sessionstore.SQLStore, the server-side session
-- store replaced by the chunked cookie store. No code has read or written this
-- table since that change, so any remaining rows are stale sessions that were
-- already unusable.
DROP INDEX IF EXISTS idx_httpsess_expires;
DROP TABLE IF EXISTS http_sessions;
