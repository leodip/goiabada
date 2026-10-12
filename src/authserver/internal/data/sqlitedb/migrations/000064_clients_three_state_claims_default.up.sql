-- Every client's two "Include OpenID Connect claims" choices hold one of their three values (#562).
--
-- include_open_id_connect_claims_in_access_token and include_open_id_connect_claims_in_id_token
-- each take on, off or default, default following the global setting of the same name. Until this
-- release the admin API's client creation and dynamic client registration wrote "" to the ID token
-- column, overriding its 'default' default, so every client either created held a value the admin
-- console's Tokens tab offers no choice for: the tab showed none selected and refused to save as
-- loaded. Both paths now write default; this does the same for the clients already created.
--
-- Every value other than on, off and default becomes default, in either column, compared exactly:
-- issuance applies a client's choice only when it is exactly on or off, and reads anything else as
-- the global setting, so no token changes.
--
-- The down migration changes nothing: once applied, a default written here can't be told from one
-- an administrator saved since.
UPDATE clients SET include_open_id_connect_claims_in_access_token = 'default'
 WHERE include_open_id_connect_claims_in_access_token NOT IN ('on', 'off', 'default');

UPDATE clients SET include_open_id_connect_claims_in_id_token = 'default'
 WHERE include_open_id_connect_claims_in_id_token NOT IN ('on', 'off', 'default');
