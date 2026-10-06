-- Migration 000059 down: re-add users.phone_number_verification_code_encrypted and
-- users.phone_number_verification_code_issued_at with their original type and nullability, so
-- the previous release, whose user statements still name both columns, can read the table (#471
-- decision 9).
--
-- The shape comes back, never the values: every row reads NULL in both, which is the state no
-- phone verification pending, the only one any release since v0.7 has written.
ALTER TABLE users ADD COLUMN phone_number_verification_code_encrypted BLOB NULL;
ALTER TABLE users ADD COLUMN phone_number_verification_code_issued_at DATETIME NULL;
