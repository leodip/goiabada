-- Migration 000048 down: re-add users.otp_secret with its original type and nullability.
--
-- The shape comes back, never the values. The plaintext seeds this column held are not recorded
-- anywhere else -- otp_secret_encrypted carries the ciphertext, and nothing writes back down to
-- plaintext -- so every row reads NULL here after a roll back. That is the same promise 000047's
-- down makes.
ALTER TABLE users ADD COLUMN otp_secret TEXT NULL;
