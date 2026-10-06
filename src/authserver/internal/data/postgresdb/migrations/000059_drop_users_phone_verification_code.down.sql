-- Migration 000059 down: re-add users.phone_number_verification_code_encrypted and
-- users.phone_number_verification_code_issued_at with the type and nullability 000001 gave them,
-- so the previous release can read the table (#471 decision 9). The shape comes back, never the
-- values: every row reads NULL in both.
ALTER TABLE users
    ADD COLUMN phone_number_verification_code_encrypted BYTEA NULL,
    ADD COLUMN phone_number_verification_code_issued_at TIMESTAMP(6) NULL;
