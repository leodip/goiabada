-- A POST to /auth/authorize is parked in a row and answered with a 303 to a GET (#246, #437).
--
-- A cross-site POST arrives without the browser's SameSite=Lax session cookie, so an answer
-- that began the ceremony from it would set a new cookie over the one the browser holds and
-- lose the pointer to a session already signed in. The POST therefore writes nothing to the
-- browser's own session row: it stores the request here and redirects to a GET carrying
-- ?request_handle=<handle>. That GET is a top-level safe navigation, which does carry the Lax
-- cookie, and it consumes the row and runs the ceremony from what it held.
--
-- handle_hash is an unsalted SHA-256 hex digest of the handle and never the handle, the shape
-- migrations 000028 and 000035 established: every incidental exposure of the column, a backup, a
-- slow query log, a support export, yields hashes rather than live handles. The handle is 256
-- bits from crypto/rand and single use, so a digest is enough to look a row up by.
--
-- request_form is the request's parameters, form encoded, and unbounded on purpose. It holds
-- the query and the body merged, which the server bounds at 64 KiB each, so it can exceed
-- MySQL's TEXT ceiling of 65,535 bytes while every parameter respects the bounds
-- /auth/authorize applies (MySQL uses LONGTEXT, as browser_sessions.data does). A bound on the
-- column would refuse a request the endpoint accepts.
--
-- The UNIQUE index on handle_hash is the lookup key. The plain index on expires_at serves the
-- background worker's sweep, which deletes on that column alone. A row is used once: consuming
-- it deletes it, and only the statement that deleted it may answer with what it held.
CREATE TABLE authorize_requests (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at DATETIME,
    updated_at DATETIME,
    handle_hash TEXT NOT NULL,
    request_form TEXT NOT NULL,
    expires_at DATETIME NOT NULL
);
CREATE UNIQUE INDEX idx_authorize_requests_handle_hash ON authorize_requests(handle_hash);
CREATE INDEX idx_authorize_requests_expires_at ON authorize_requests(expires_at);
