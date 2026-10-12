-- Every client's two "Include OpenID Connect claims" choices hold one of their three values (#562).
-- See the sqlite migration of the same number for why, and why no token changes.
--
-- Both columns' collation, utf8mb4_0900_as_cs, compares case and trailing spaces exactly but is
-- linguistic, so 'o' U+00AD 'n' (a soft hyphen, which it ignores) = 'on' holds. Comparing the
-- bytes makes the comparison exact, as on SQLite and PostgreSQL, since issuance reads such a value
-- as the global setting. A binary string is never padded, so trailing spaces still count.
UPDATE `clients` SET `include_open_id_connect_claims_in_access_token` = 'default'
 WHERE CAST(`include_open_id_connect_claims_in_access_token` AS BINARY) NOT IN ('on', 'off', 'default');

UPDATE `clients` SET `include_open_id_connect_claims_in_id_token` = 'default'
 WHERE CAST(`include_open_id_connect_claims_in_id_token` AS BINARY) NOT IN ('on', 'off', 'default');
