-- A self-registered client has both legacy flows off on itself (#542 review).
--
-- A registration can't ask for the implicit or password grant, but until this release the client it
-- created left implicit_grant_enabled and resource_owner_password_credentials_enabled NULL, and a
-- NULL switch follows the global setting. So turning the implicit flow or ROPC on under Admin,
-- General handed it to every client anyone had registered, whatever its registration said. New
-- registrations now write both switches off; this does the same for the clients already
-- registered.
--
-- Only a NULL becomes off. A value an administrator chose on the client's OAuth2 flows tab, on or
-- off, is kept: an administrator who reviewed a self-registered client and turned a flow on for it
-- meant it. Clients created in the admin console are untouched, their NULL meaning "follow the
-- global setting" as the console offers.
--
-- The marker misses one kind of client, the limit 000029 documents: a self-registered client an
-- administrator renamed before that release lost the dcr_ prefix 000029's backfill read, so it
-- carries created_via_dcr = 0 and keeps following the global settings. Nothing in the database
-- tells it from a client an administrator created, so this can't reach it; the 1.7.0 release notes
-- ask operators who ran dynamic client registration before 000029 to find such clients and turn
-- both flows off on them by hand.
--
-- The down migration changes nothing: once applied, an off written here can't be told from one an
-- administrator saved since.
UPDATE clients SET implicit_grant_enabled = 0
 WHERE created_via_dcr = 1 AND implicit_grant_enabled IS NULL;

UPDATE clients SET resource_owner_password_credentials_enabled = 0
 WHERE created_via_dcr = 1 AND resource_owner_password_credentials_enabled IS NULL;
