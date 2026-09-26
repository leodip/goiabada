-- parity: mysql, postgres and mssql only. SQLite stores all three columns as TEXT, which has no width.
--
-- Widens the three columns a client's URLs are stored in to the bounds the handlers now enforce
-- (#428): redirect_uris.uri and codes.redirect_uri to 2048, web_origins.origin to 267. See the
-- MySQL migration of the same number for why each number, and why codes.redirect_uri moves with
-- redirect_uris.uri.
--
-- The handlers bound all three in bytes, and PostgreSQL counts a VARCHAR's width in characters, so
-- a value they admit is never wider than the column. Raising a VARCHAR's limit is a catalog change
-- with no table rewrite, including under idx_web_origins_origin_client. ALTER COLUMN ... TYPE keeps
-- the column's NOT NULL and its collation.
ALTER TABLE redirect_uris ALTER COLUMN uri TYPE VARCHAR(2048);

ALTER TABLE codes ALTER COLUMN redirect_uri TYPE VARCHAR(2048);

ALTER TABLE web_origins ALTER COLUMN origin TYPE VARCHAR(267);
