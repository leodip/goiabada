-- A pending TOTP enrolment on the user row (#247). See the sqlite migration of the same number for
-- what the columns are for, why the encrypted one holds the otpauth:// URL rather than the bare
-- secret, and why neither needs a default.
--
-- The types are the ones the three existing pending-credential pairs on this table already use on
-- this engine: longblob for the ciphertext and datetime(6) for the timestamp.
ALTER TABLE `users` ADD COLUMN `otp_enrollment_secret_encrypted` longblob DEFAULT NULL;
ALTER TABLE `users` ADD COLUMN `otp_enrollment_issued_at` datetime(6) DEFAULT NULL;
