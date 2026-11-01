-- A client's Remember consent setting (#711 decisions 1, 4 and 7).
--
-- clients.remember_consent decides whether a user's earlier approval may skip the consent screen
-- for this client. The server reads it for a public client only (record.Client.RemembersConsent): a
-- public client has no secret, so nothing proves an authorization request comes from it rather than
-- from another app using its client ID, and RFC 8252 section 8.6 and RFC 6749 section 10.2 say such
-- a request SHOULD be processed as if no previous request had been approved. A confidential client
-- always remembers consent, and every writer keeps its row on, so the row, the admin API's answer
-- and the console agree with what the server does.
--
-- The default is off, so a public row inserted without the column fails closed. The backfill turns
-- it on for every confidential client and leaves every public client off: an administrator who can
-- vouch for a public client's identity turns it on for that client.
--
-- The down migration drops the column, and with it every setting an administrator turned on since.
ALTER TABLE clients ADD COLUMN remember_consent numeric NOT NULL DEFAULT 0;

UPDATE clients SET remember_consent = 1 WHERE is_public = 0;
