-- Back to the width the four columns carried before #632.
--
-- Each ALTER narrows the column to 64 UTF-16 units, so a stored value that grew past that is
-- refused with Msg 2628 and the file rolls back, with the value whole rather than cut to an
-- address that is no longer the person's. That is what restoring the previous shape means here.
--
-- SQL Server refuses to narrow a column an index covers (Msg 5074), so idx_email and
-- idx_pre_reg_email come off around their columns' ALTERs and go back exactly as 000040 recreated
-- them. Atomic for the reason the up file gives: without the pair below, a refusal after a DROP
-- INDEX would leave that index gone, and the unique one on users.email is what keeps two
-- accounts from sharing an address.
SET XACT_ABORT ON;
BEGIN TRANSACTION;

DROP INDEX [idx_email] ON [users];
ALTER TABLE [users] ALTER COLUMN [email] NVARCHAR(64) COLLATE Latin1_General_100_CS_AS_KS_WS_SC_UTF8 NULL;
CREATE UNIQUE INDEX [idx_email] ON [users]([email]);

DROP INDEX [idx_pre_reg_email] ON [pre_registrations];
ALTER TABLE [pre_registrations] ALTER COLUMN [email] NVARCHAR(64) COLLATE Latin1_General_100_CS_AS_KS_WS_SC_UTF8 NULL;
CREATE INDEX [idx_pre_reg_email] ON [pre_registrations]([email]);

ALTER TABLE [settings] ALTER COLUMN [smtp_from_email] NVARCHAR(64) COLLATE Latin1_General_100_CS_AS_KS_WS_SC_UTF8 NULL;

ALTER TABLE [settings] ALTER COLUMN [smtp_username] NVARCHAR(64) COLLATE Latin1_General_100_CS_AS_KS_WS_SC_UTF8 NULL;

COMMIT TRANSACTION;
SET XACT_ABORT OFF;
