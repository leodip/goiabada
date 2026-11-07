-- The DPoP proofs the auth server has accepted, so each is accepted once (#42 decision 9, RFC 9449
-- section 11.1). A request whose proof passes every other check, and that would otherwise succeed,
-- stores the proof here just before anything is minted or served; a second request with the same
-- proof finds the key taken, and is refused as a replay. The table is shared by every instance
-- sharing the database, so a proof captured at one cannot be replayed at another.
--
-- proof_hash is the unsalted SHA-256 hex digest of the proof's normalized htu, a space, and its
-- jti: never the jti itself, which is the client's own value and unbounded. It is the primary key,
-- and the key is what makes the write atomic: a second insert of one proof fails on every engine,
-- and that failure is the replay. Nothing references a proof, and nothing is backfilled: before
-- this migration no proof was stored.
--
-- expires_at is the last moment the proof could still be accepted: at the token endpoint the expiry
-- of the nonce it carries. Past it the proof is refused for that alone, so the row has nothing left
-- to refuse, and the background worker deletes it on that column, which the plain index serves.
CREATE TABLE dpop_proofs (
    proof_hash TEXT NOT NULL PRIMARY KEY,
    expires_at DATETIME NOT NULL
);
CREATE INDEX idx_dpop_proofs_expires_at ON dpop_proofs(expires_at);
