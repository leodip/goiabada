-- Reverses migration 000070 (#676). See the sqlite migration of the same number for what is lost:
-- every recorded deletion, so a token issued to a deleted client in the same second a new client
-- took its identifier is live again until it expires.
DROP TABLE deleted_clients;
