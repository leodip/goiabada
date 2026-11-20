-- Lower to urn:goiabada:level1 every stored sign-in at urn:goiabada:level2_mandatory whose methods
-- name neither otp nor recovery_code (#199). See the sqlite migration of the same number for why
-- every such row is lowered and why to level1.
--
-- A method is named when the space-separated list holds exactly that name: the padded list and
-- name match whole names only. The column's collation, utf8mb4_0900_as_cs, is case-sensitive but
-- linguistic, and ignores some characters, such as the soft hyphen 000065 measured. Searching the
-- bytes makes the match exact, as on SQLite and PostgreSQL: LOCATE() is byte-wise when an argument
-- is a binary string.
UPDATE `codes` SET `acr_level` = 'urn:goiabada:level1'
WHERE `acr_level` = 'urn:goiabada:level2_mandatory'
  AND LOCATE(' otp ', CAST(CONCAT(' ', `auth_methods`, ' ') AS BINARY)) = 0
  AND LOCATE(' recovery_code ', CAST(CONCAT(' ', `auth_methods`, ' ') AS BINARY)) = 0;
