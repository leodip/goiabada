-- Every client's two "Include OpenID Connect claims" choices hold one of their three values (#562).
-- See the sqlite migration of the same number for why, and why no token changes. Both columns'
-- collation, utf8mb4_0900_as_cs, compares case and trailing spaces exactly.
UPDATE `clients` SET `include_open_id_connect_claims_in_access_token` = 'default'
 WHERE `include_open_id_connect_claims_in_access_token` NOT IN ('on', 'off', 'default');

UPDATE `clients` SET `include_open_id_connect_claims_in_id_token` = 'default'
 WHERE `include_open_id_connect_claims_in_id_token` NOT IN ('on', 'off', 'default');
