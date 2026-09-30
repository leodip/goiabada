-- A POST to /auth/authorize is parked in a row and answered with a 303 to a GET (#246, #437). See
-- the sqlite migration of the same number for why, why handle_hash holds a digest rather than the
-- handle, why request_form is unbounded, and what each index serves.
--
-- Both string columns are pinned to the case-sensitive collation per column, as every string
-- column is: the database's own default is whatever an operator pre-created it with, and an
-- unpinned column would compare a handle case-insensitively there (#283).
CREATE TABLE [authorize_requests] (
    [id] BIGINT IDENTITY(1,1) PRIMARY KEY,
    [created_at] DATETIME2(6) NULL,
    [updated_at] DATETIME2(6) NULL,
    [handle_hash] NVARCHAR(64) COLLATE Latin1_General_100_CS_AS_KS_WS_SC_UTF8 NOT NULL,
    [request_form] NVARCHAR(MAX) COLLATE Latin1_General_100_CS_AS_KS_WS_SC_UTF8 NOT NULL,
    [expires_at] DATETIME2(6) NOT NULL
);
CREATE UNIQUE INDEX [idx_authorize_requests_handle_hash] ON [authorize_requests]([handle_hash]);
CREATE INDEX [idx_authorize_requests_expires_at] ON [authorize_requests]([expires_at]);
