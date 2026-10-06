-- Migration 000059: drop users.phone_number_verification_code_encrypted and
-- users.phone_number_verification_code_issued_at (#471 decision 8).
--
-- Both belonged to the SMS phone verification that v0.7 removed (fb9157a4), and nothing has read
-- or written them since but the generic user insert and the whole-row save #471 retires. A row from
-- before v0.7 may still hold a ciphertext and an issued-at here that nothing can use.
--
-- Both columns are nullable on all four engines, carry no default and are in no index, so nothing
-- has to be dropped before them. The Go fields record.User.PhoneNumberVerificationCodeEncrypted
-- and PhoneNumberVerificationCodeIssuedAt go in the same commit, because sqlbuilder derives every
-- users statement's column list from the struct tags, and so does the first column's entry in the
-- key rotation's list of encrypted columns.
ALTER TABLE users DROP COLUMN phone_number_verification_code_encrypted;
ALTER TABLE users DROP COLUMN phone_number_verification_code_issued_at;
