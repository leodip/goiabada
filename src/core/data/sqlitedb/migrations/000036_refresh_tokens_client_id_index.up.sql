-- refresh_tokens(client_id) is indexed on MySQL, PostgreSQL and SQL Server and was
-- never indexed on SQLite (#282). Migration 000011 rebuilt refresh_tokens and restored
-- only idx_refresh_token_jti, and 000024 later added idx_refresh_tokens_user_id and not
-- the client one, so SQLite has run without it since.
--
-- What reads it: deleteRefreshTokensByColumn filters on client_id when DeleteClient
-- clears a client's tokens, which is a full table scan on SQLite and a seek elsewhere.
-- Nothing is incorrect without it; the divergence is the point.
CREATE INDEX idx_refresh_tokens_client_id ON refresh_tokens(client_id);
