-- Drop pre_registrations.password_hash (#207 decision 2). See the sqlite migration of the same
-- number for why nothing writes or reads the column any more, and which Go code goes with it.
--
-- The column is in no index and carries no default on this engine, so nothing has to be dropped
-- before it.
ALTER TABLE pre_registrations DROP COLUMN password_hash;
