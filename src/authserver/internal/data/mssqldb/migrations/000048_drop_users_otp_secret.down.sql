-- Migration 000048 down: re-add users.otp_secret with its original type, collation and spelled
-- nullability. The shape comes back, never the values: the plaintext seeds are recorded nowhere
-- else, so every row reads NULL here after a roll back.
ALTER TABLE [users] ADD [otp_secret] NVARCHAR(64) COLLATE Latin1_General_100_CS_AS_KS_WS_SC_UTF8 NULL;
