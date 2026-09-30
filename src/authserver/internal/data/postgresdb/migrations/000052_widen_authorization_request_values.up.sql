-- parity: mysql, postgres and mssql only. SQLite stores all five columns as TEXT, which has no width.
--
-- Widens the five columns an authorization request's free-form values are stored in from 512 to
-- 2048 (#437): codes.state, codes.nonce, codes.scope, refresh_tokens.scope and
-- user_consents.scope. See the MySQL migration of the same number for why each, and why the three
-- scope columns move together.
--
-- The handlers bound all three values in bytes, and PostgreSQL counts a VARCHAR's width in
-- characters, so a value they admit is never wider than the column. Raising a VARCHAR's limit is a
-- catalog change with no table rewrite. ALTER COLUMN ... TYPE keeps the column's NOT NULL and its
-- collation, and none of the five carries a default.
ALTER TABLE codes
    ALTER COLUMN state TYPE VARCHAR(2048),
    ALTER COLUMN nonce TYPE VARCHAR(2048),
    ALTER COLUMN scope TYPE VARCHAR(2048);

ALTER TABLE refresh_tokens ALTER COLUMN scope TYPE VARCHAR(2048);

ALTER TABLE user_consents ALTER COLUMN scope TYPE VARCHAR(2048);
