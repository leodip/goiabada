-- Drop users.phone_number_verification_code_encrypted and users.phone_number_verification_code_issued_at
-- (#471 decision 8). See the sqlite migration of the same number for why nothing reads or writes
-- them any more, and which Go code goes with them.
--
-- Both columns are nullable, carry no default and are in no index on this engine, so nothing has
-- to be dropped before them.
ALTER TABLE users
    DROP COLUMN phone_number_verification_code_encrypted,
    DROP COLUMN phone_number_verification_code_issued_at;
