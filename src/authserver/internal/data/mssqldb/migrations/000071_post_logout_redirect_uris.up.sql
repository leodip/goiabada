-- A client's sign-out redirect URIs (#147 decision 2). See the sqlite migration of the same number
-- for why and for the six questions.
--
-- uri is NVARCHAR(2048), the width of redirect_uris.uri, and is pinned to the case-sensitive
-- collation per column, as every string column is: the database's own default is whatever an
-- operator pre-created it with (#283).
CREATE TABLE [post_logout_redirect_uris] (
    [id] BIGINT IDENTITY(1,1) PRIMARY KEY,
    [created_at] DATETIME2(6) NULL,
    [uri] NVARCHAR(2048) COLLATE Latin1_General_100_CS_AS_KS_WS_SC_UTF8 NOT NULL,
    [client_id] BIGINT NOT NULL,
    CONSTRAINT [fk_clients_post_logout_redirect_uris] FOREIGN KEY ([client_id])
        REFERENCES [clients] ([id]) ON DELETE CASCADE
);
