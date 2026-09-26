-- Back to the width the three columns carried before #428.
--
-- Each ALTER narrows the column to 256 UTF-16 units, so a row that grew past that is refused with
-- Msg 2628 and the file rolls back. That is what restoring the previous shape means here.
--
-- SQL Server refuses to narrow a column an index covers (Msg 5074), so idx_web_origins_origin_client
-- comes off around the web_origins ALTER and goes back exactly as 000040 recreated it. Atomic for
-- the reason the up file gives: without the pair below, a failure after the DROP INDEX would leave
-- the unique index gone.
SET XACT_ABORT ON;
BEGIN TRANSACTION;

ALTER TABLE [redirect_uris] ALTER COLUMN [uri] NVARCHAR(256) COLLATE Latin1_General_100_CS_AS_KS_WS_SC_UTF8 NOT NULL;

ALTER TABLE [codes] ALTER COLUMN [redirect_uri] NVARCHAR(256) COLLATE Latin1_General_100_CS_AS_KS_WS_SC_UTF8 NOT NULL;

DROP INDEX [idx_web_origins_origin_client] ON [web_origins];
ALTER TABLE [web_origins] ALTER COLUMN [origin] NVARCHAR(256) COLLATE Latin1_General_100_CS_AS_KS_WS_SC_UTF8 NOT NULL;
CREATE UNIQUE INDEX [idx_web_origins_origin_client] ON [web_origins]([origin], [client_id]);

COMMIT TRANSACTION;
SET XACT_ABORT OFF;
