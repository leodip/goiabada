-- Any pending enrolment in flight is discarded: see the sqlite migration for why that is harmless.
ALTER TABLE `users` DROP COLUMN `otp_enrollment_issued_at`;
ALTER TABLE `users` DROP COLUMN `otp_enrollment_secret_encrypted`;
