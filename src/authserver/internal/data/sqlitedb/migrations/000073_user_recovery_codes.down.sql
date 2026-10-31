-- Reverses migration 000073 (#257). DROP TABLE takes the index and the foreign key with it.
--
-- Every user's recovery codes are lost: nobody can sign in with one until they get a new set.
DROP TABLE user_recovery_codes;
