-- The DPoP proofs the auth server has accepted, so each is accepted once (#42 decision 9). See the
-- sqlite migration of the same number for why, what proof_hash holds and what the index serves.
--
-- proof_hash is varchar(64), a SHA-256 hex digest, and the table is pinned to the case- and
-- accent-sensitive collation every table here carries (#283), so the primary key means what it
-- says.
CREATE TABLE `dpop_proofs` (
    `proof_hash` varchar(64) NOT NULL,
    `expires_at` datetime(6) NOT NULL,
    PRIMARY KEY (`proof_hash`),
    KEY `idx_dpop_proofs_expires_at` (`expires_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_as_cs;
