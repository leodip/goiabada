-- Every client's two "Include OpenID Connect claims" choices hold one of their three values (#562).
-- See the sqlite migration of the same number for why, and why no token changes.
--
-- The columns' collation compares case exactly but is linguistic, so 'o' U+00AD 'n' (a soft
-- hyphen, which it ignores) = N'on' holds; Latin1_General_100_BIN2 compares code points instead.
-- SQL Server also pads the shorter side with spaces before comparing, under any collation, so
-- 'on ' = N'on' holds; a marker appended to both sides counts trailing spaces. Together they make
-- the comparison exact, as on SQLite and PostgreSQL, since issuance reads either value as the
-- global setting.
UPDATE [clients] SET [include_open_id_connect_claims_in_access_token] = N'default'
 WHERE [include_open_id_connect_claims_in_access_token] COLLATE Latin1_General_100_BIN2 + N'|'
       NOT IN (N'on|', N'off|', N'default|');

UPDATE [clients] SET [include_open_id_connect_claims_in_id_token] = N'default'
 WHERE [include_open_id_connect_claims_in_id_token] COLLATE Latin1_General_100_BIN2 + N'|'
       NOT IN (N'on|', N'off|', N'default|');
