-- A pending TOTP enrolment on the user row (#247). See the sqlite migration of the same number for
-- what the columns are for, why the encrypted one holds the otpauth:// URL rather than the bare
-- secret, and why neither needs a default.
--
-- The types are the ones the three existing pending-credential pairs on this table already use on
-- this engine: VARBINARY(MAX) for the ciphertext and DATETIME2(6) for the timestamp.
--
-- No DEFAULT, so unlike 000024, 000029 and 000031 there is no named default constraint here and the
-- down migration below drops the columns directly. That is only safe because both columns are
-- nullable: a NOT NULL column added to a populated table needs a default, and a default on SQL
-- Server is a constraint that has to be dropped by name before its column can go.
ALTER TABLE [users] ADD [otp_enrollment_secret_encrypted] VARBINARY(MAX) NULL;
ALTER TABLE [users] ADD [otp_enrollment_issued_at] DATETIME2(6) NULL;
