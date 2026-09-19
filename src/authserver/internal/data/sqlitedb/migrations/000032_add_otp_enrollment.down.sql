-- Any pending enrolment in flight is discarded, which costs a user nothing beyond loading the
-- enrolment page again: the pair is short-lived by construction and no authenticator depends on it.
ALTER TABLE users DROP COLUMN otp_enrollment_issued_at;
ALTER TABLE users DROP COLUMN otp_enrollment_secret_encrypted;
