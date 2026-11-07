-- Migration 000086 down: drop the DPoP binding of refresh-token families, so every family reads
-- unbound again, as every one did before 000086. Nothing indexes or constrains the column, which is
-- SQLite's requirement before DROP COLUMN.
ALTER TABLE refresh_tokens DROP COLUMN dpop_jkt;
