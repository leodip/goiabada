-- Reverses migration 000068 (#676). DROP TABLE takes the index and the primary key with it.
--
-- Every stored jti is lost, and with it the revocation of each access token without a grant that
-- was revoked and has not yet expired: those tokens are live again until they expire.
DROP TABLE revoked_access_tokens;
