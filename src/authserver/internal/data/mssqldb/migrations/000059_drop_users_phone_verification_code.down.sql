-- Migration 000059 down: re-add users.phone_number_verification_code_encrypted and
-- users.phone_number_verification_code_issued_at with the type 000001 gave them and their
-- nullability spelled, so the previous release can read the table (#471 decision 9). The shape
-- comes back, never the values: every row reads NULL in both.
--
-- No EXEC wrapper, as for 000048's down: the statement adds the columns and nothing in the batch
-- names them afterwards.
ALTER TABLE [users] ADD
    [phone_number_verification_code_encrypted] VARBINARY(MAX) NULL,
    [phone_number_verification_code_issued_at] DATETIME2(6) NULL;
