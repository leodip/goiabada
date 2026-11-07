-- Reverses migration 000085 (#42). DROP TABLE takes the index and the primary key with it.
--
-- Every stored proof is lost, so a proof accepted before the rollback whose nonce has not yet
-- expired could be accepted once more.
DROP TABLE dpop_proofs;
