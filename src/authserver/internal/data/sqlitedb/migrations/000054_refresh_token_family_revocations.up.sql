-- A revoked refresh token family is recorded, and a child born into one is refused (#132, #259,
-- #437).
--
-- A rotation claims its parent and inserts its child in separate statements, so between them the
-- family has no live member. A replay's containment, or a client made public, that sweeps the
-- family's live rows in that window finds nothing to revoke and misses the child the rotation
-- then inserts. The record closes it: containment and the client's revocation write the family's
-- row in the same transaction as the revocation, the refresh validator refuses a token whose
-- family has a row, and the rotation checks the row again inside its own transaction. A child
-- that commits in the gap is born refused, the shape migrations 000026 and 000045 gave the
-- authorization code.
--
-- The six questions (reference/migrations.md 6): (1) all four engines. (2) first_refresh_token_jti
-- is pinned case-sensitive as refresh_tokens.first_refresh_token_jti is, and is the same width,
-- 64; reason is a short pinned string. (3) The lookup compares the jti with =, so the data layer
-- compares the row it got back against the jti it asked for in Go. (4) The jti is the primary key:
-- a family is revoked once, and the first reason and time stay. (5) No existing row changes
-- meaning: families contained before this migration keep their revoked rows, which is what
-- detects their replay, and nothing is backfilled. (6) Each schema.golden gains the table.
--
-- There is no foreign key: first_refresh_token_jti is not unique in refresh_tokens, which holds
-- one row per member. The background worker deletes a record once no refresh token of its family
-- remains.
CREATE TABLE refresh_token_family_revocations (
    first_refresh_token_jti TEXT NOT NULL PRIMARY KEY,
    reason TEXT NOT NULL,
    revoked_at DATETIME NOT NULL
);
