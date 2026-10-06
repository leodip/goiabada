-- Drop users.phone_number_verification_code_encrypted and users.phone_number_verification_code_issued_at
-- (#471 decision 8). See the sqlite migration of the same number for why nothing reads or writes
-- them any more, and which Go code goes with them.
--
-- Both columns are nullable, carry no DEFAULT constraint and are in no index on this engine, so
-- nothing has to be dropped by name before them.
--
-- No EXEC wrapper, on 000033's reasoning: this adds no column and names only columns that already
-- exist, so a plain statement resolves at batch compile time.
ALTER TABLE [users] DROP COLUMN [phone_number_verification_code_encrypted], [phone_number_verification_code_issued_at];
