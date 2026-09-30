-- Back to the width the five columns carried before #437.
--
-- Each ALTER narrows the column to 512 UTF-16 units, so a row that grew past that is refused with
-- Msg 2628 and the file rolls back. That is what restoring the previous shape means here. Atomic
-- for the reason the up file gives.
SET XACT_ABORT ON;
BEGIN TRANSACTION;

ALTER TABLE [codes] ALTER COLUMN [state] NVARCHAR(512) COLLATE Latin1_General_100_CS_AS_KS_WS_SC_UTF8 NOT NULL;

ALTER TABLE [codes] ALTER COLUMN [nonce] NVARCHAR(512) COLLATE Latin1_General_100_CS_AS_KS_WS_SC_UTF8 NOT NULL;

ALTER TABLE [codes] ALTER COLUMN [scope] NVARCHAR(512) COLLATE Latin1_General_100_CS_AS_KS_WS_SC_UTF8 NOT NULL;

ALTER TABLE [refresh_tokens] ALTER COLUMN [scope] NVARCHAR(512) COLLATE Latin1_General_100_CS_AS_KS_WS_SC_UTF8 NOT NULL;

ALTER TABLE [user_consents] ALTER COLUMN [scope] NVARCHAR(512) COLLATE Latin1_General_100_CS_AS_KS_WS_SC_UTF8 NOT NULL;

COMMIT TRANSACTION;
SET XACT_ABORT OFF;
