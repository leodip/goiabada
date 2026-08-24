-- Any pending enrolment in flight is discarded: see the sqlite migration for why that is harmless.
-- No constraints to drop first, because the up migration gave neither column a default.
ALTER TABLE [users] DROP COLUMN [otp_enrollment_issued_at];
ALTER TABLE [users] DROP COLUMN [otp_enrollment_secret_encrypted];
