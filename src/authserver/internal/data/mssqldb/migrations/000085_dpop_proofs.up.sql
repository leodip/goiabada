-- The DPoP proofs the auth server has accepted, so each is accepted once (#42 decision 9). See the
-- sqlite migration of the same number for why, what proof_hash holds and what the index serves.
--
-- proof_hash is pinned to the case-sensitive collation per column, as every string column is: the
-- database's own default is whatever an operator pre-created it with (#283).
CREATE TABLE [dpop_proofs] (
    [proof_hash] NVARCHAR(64) COLLATE Latin1_General_100_CS_AS_KS_WS_SC_UTF8 NOT NULL PRIMARY KEY,
    [expires_at] DATETIME2(6) NOT NULL
);
CREATE INDEX [idx_dpop_proofs_expires_at] ON [dpop_proofs]([expires_at]);
