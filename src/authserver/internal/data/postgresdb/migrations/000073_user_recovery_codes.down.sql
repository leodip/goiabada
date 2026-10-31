-- Reverses migration 000073 (#257). See the sqlite migration of the same number for what is lost:
-- every user's recovery codes.
DROP TABLE user_recovery_codes;
