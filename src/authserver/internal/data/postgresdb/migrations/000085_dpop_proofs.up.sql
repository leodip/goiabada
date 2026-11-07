-- The DPoP proofs the auth server has accepted, so each is accepted once (#42 decision 9). See the
-- sqlite migration of the same number for why, what proof_hash holds and what the index serves.
-- PostgreSQL compares strings byte-wise, so proof_hash needs no collation pin.
CREATE TABLE dpop_proofs (
    proof_hash character varying(64) NOT NULL PRIMARY KEY,
    expires_at timestamp(6) without time zone NOT NULL
);
CREATE INDEX idx_dpop_proofs_expires_at ON dpop_proofs(expires_at);
