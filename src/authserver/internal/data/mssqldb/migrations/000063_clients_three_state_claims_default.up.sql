-- Every client's two "Include OpenID Connect claims" choices hold one of their three values (#562).
-- See the sqlite migration of the same number for why, and why no token changes.
--
-- SQL Server pads the shorter side with spaces before comparing, so 'on ' = N'on' holds; a marker
-- appended to both sides makes the comparison exact, as on the other three engines, since issuance
-- reads 'on ' as the global setting. The collation compares case exactly.
UPDATE [clients] SET [include_open_id_connect_claims_in_access_token] = N'default'
 WHERE [include_open_id_connect_claims_in_access_token] + N'|' NOT IN (N'on|', N'off|', N'default|');

UPDATE [clients] SET [include_open_id_connect_claims_in_id_token] = N'default'
 WHERE [include_open_id_connect_claims_in_id_token] + N'|' NOT IN (N'on|', N'off|', N'default|');
