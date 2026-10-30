-- Reverses migration 000068 (#676). See the sqlite migration of the same number for what is lost:
-- every stored jti, so each access token without a grant that was revoked is live again until it
-- expires.
DROP TABLE [revoked_access_tokens];
