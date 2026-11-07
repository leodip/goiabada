-- The DPoP key a public client's refresh-token family is bound to (#42 decision 11). See the sqlite
-- migration of the same number for what the column holds, who writes it, and why existing rows land
-- NULL with no backfill.
--
-- varchar(64), the width of the jti columns beside it; a thumbprint is 43 characters. No COLLATE
-- clause: refresh_tokens is declared utf8mb4_0900_as_cs, and a column added without one inherits the
-- table's, so the thumbprint compares case-sensitively, as base64url needs.
ALTER TABLE `refresh_tokens` ADD COLUMN `dpop_jkt` varchar(64) DEFAULT NULL;
