-- A POST to /auth/authorize is parked in a row and answered with a 303 to a GET (#246, #437). See
-- the sqlite migration of the same number for why, why handle_hash holds a digest rather than the
-- handle, why request_form is unbounded, and what each index serves. PostgreSQL compares strings
-- byte-wise, so neither string column needs a collation pin.
CREATE TABLE authorize_requests (
    id BIGSERIAL PRIMARY KEY,
    created_at timestamp(6) without time zone,
    updated_at timestamp(6) without time zone,
    handle_hash character varying(64) NOT NULL,
    request_form TEXT NOT NULL,
    expires_at timestamp(6) without time zone NOT NULL
);
CREATE UNIQUE INDEX idx_authorize_requests_handle_hash ON authorize_requests(handle_hash);
CREATE INDEX idx_authorize_requests_expires_at ON authorize_requests(expires_at);
