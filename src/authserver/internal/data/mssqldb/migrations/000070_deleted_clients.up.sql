-- A deleted client's identifier and the moment it was deleted (#676 decision 6). See the sqlite
-- migration of the same number for why, for the six questions and for why rows are kept.
--
-- The identifier is pinned to the case-sensitive collation per column, as every string column is:
-- the database's own default is whatever an operator pre-created it with, and an unpinned column
-- would compare an identifier case-insensitively there (#283).
CREATE TABLE [deleted_clients] (
    [client_identifier] NVARCHAR(40) COLLATE Latin1_General_100_CS_AS_KS_WS_SC_UTF8 NOT NULL PRIMARY KEY,
    [deleted_at] DATETIME2(6) NOT NULL
);
