-- Drop users.otp_secret, the plaintext TOTP seed column (#98, #262). See the sqlite migration of
-- the same number for why the column has no reader left, which Go code goes with it, and why an
-- upgrade must pass through 1.6.x rather than coming straight from 1.5.x.
--
-- The column is nullable, carries no DEFAULT constraint and is in no index on this engine, so
-- nothing has to be dropped by name before it.
--
-- No EXEC wrapper, on 000033's reasoning: this adds no column and names only a column that already
-- exists, so a plain statement resolves at batch compile time.
ALTER TABLE [users] DROP COLUMN [otp_secret];
