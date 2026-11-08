-- The DPoP key an authorization code is bound to (#42 decision 14). See the sqlite migration of the
-- same number for what the column holds, who writes it, and why existing rows land NULL with no
-- backfill.
--
-- varchar(64), the width of refresh_tokens.dpop_jkt; a thumbprint is 43 characters. No COLLATE
-- clause: codes is declared utf8mb4_0900_as_cs since 000040, and a column added without one inherits
-- the table's, so the thumbprint compares case-sensitively, as base64url needs.
ALTER TABLE `codes` ADD COLUMN `dpop_jkt` varchar(64) DEFAULT NULL;
