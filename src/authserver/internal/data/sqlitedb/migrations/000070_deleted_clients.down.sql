-- Reverses migration 000070 (#676). DROP TABLE takes the primary key with it.
--
-- Every recorded deletion is lost: a token issued to a deleted client in the same second a new
-- client took its identifier is live again until it expires.
DROP TABLE deleted_clients;
