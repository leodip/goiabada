-- Migration 000048 down: re-add users.otp_secret with its original type, collation and
-- nullability. The shape comes back, never the values: the plaintext seeds are recorded nowhere
-- else, so every row reads NULL here after a roll back.
ALTER TABLE `users` ADD COLUMN `otp_secret` VARCHAR(64) COLLATE utf8mb4_0900_as_cs NULL;
