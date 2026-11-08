-- Migration 000088 down: drop the DPoP binding of authorization codes, so every code reads as bound
-- to no key again, as every one did before 000088. Nothing indexes or constrains the column, which is
-- SQLite's requirement before DROP COLUMN.
ALTER TABLE codes DROP COLUMN dpop_jkt;
