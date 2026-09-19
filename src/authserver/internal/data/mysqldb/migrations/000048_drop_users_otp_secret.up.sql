-- Drop users.otp_secret, the plaintext TOTP seed column (#98, #262). See the sqlite migration of
-- the same number for why the column has no reader left, which Go code goes with it, and why an
-- upgrade must pass through 1.6.x rather than coming straight from 1.5.x.
--
-- The column is nullable, carries no default and is in no index on this engine, so nothing has to
-- be dropped before it.
ALTER TABLE `users` DROP COLUMN `otp_secret`;
