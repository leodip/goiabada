-- A session records when its password was entered, apart from auth_time (#542 review). See the
-- sqlite migration of the same number for why every stored session is ended, and every code not yet
-- redeemed revoked.
--
-- The order is for a rolling upgrade, where the previous release keeps serving while this one
-- migrates and goes on inserting sessions that name no password_auth_time. The column is added with
-- a throwaway default, so the ALTER succeeds whatever rows exist at that instant; the default is
-- dropped, so from then on such an insert is refused rather than stored with an invented time; and
-- only then are the sessions deleted, so every row the previous release wrote is gone. Deleting
-- first and adding the column NOT NULL after, a session inserted between the two failed the ALTER
-- and left the migration dirty. The previous release's sign-ins fail from the drop until it stops.
--
-- Refused in strict SQL mode, MySQL's default. Without it MySQL stores a zero time for the missing
-- column instead, so on such a server the previous release is stopped before this one starts, as the
-- 1.7.0 release notes say.
ALTER TABLE `user_sessions` ADD COLUMN `password_auth_time` datetime(6) NOT NULL DEFAULT '1970-01-01 00:00:00';
ALTER TABLE `user_sessions` ALTER COLUMN `password_auth_time` DROP DEFAULT;

DELETE FROM `user_sessions`;

-- Every code not yet redeemed is revoked with the sessions: see the sqlite migration.
UPDATE `codes` SET `revoked` = 1 WHERE `used` = 0 AND `revoked` = 0;
