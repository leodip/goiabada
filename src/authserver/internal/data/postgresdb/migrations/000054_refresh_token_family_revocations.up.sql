-- A revoked refresh token family is recorded, and a child born into one is refused (#132, #259,
-- #437). See the sqlite migration of the same number for why, and for the six questions.
-- PostgreSQL compares strings byte-wise, so neither string column needs a collation pin.
CREATE TABLE refresh_token_family_revocations (
    first_refresh_token_jti character varying(64) NOT NULL PRIMARY KEY,
    reason character varying(64) NOT NULL,
    revoked_at timestamp(6) without time zone NOT NULL
);
