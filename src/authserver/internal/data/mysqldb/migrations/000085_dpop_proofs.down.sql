-- Reverses migration 000085 (#42). See the sqlite migration of the same number for what is lost:
-- every stored proof, so one whose nonce has not yet expired could be accepted once more.
DROP TABLE `dpop_proofs`;
