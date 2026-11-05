-- A client's back-channel logout settings (#784 decision 14).
--
-- clients.backchannel_logout_uri is where the auth server POSTs a logout token when a session the
-- client was on ends, as OpenID Connect Back-Channel Logout 1.0 section 2.2 registers it, and empty
-- for none. clients.backchannel_logout_session_required is whether the client needs the session
-- identifier in every logout token, the same section's backchannel_logout_session_required. Both
-- are one value per client, as the document URLs of 000078 are, and every delivery already has the
-- client loaded, so they are columns of clients rather than a table of their own.
--
-- The URI is validated before it is stored, at most 2048 bytes, the width of a redirect URI.
-- Every existing client starts with neither, through the columns' defaults, so no existing client
-- is sent anything until a URI is set: there is nothing to backfill. The down migration drops both
-- columns, and every setting made since with them.
ALTER TABLE clients ADD COLUMN backchannel_logout_uri TEXT NOT NULL DEFAULT '';
ALTER TABLE clients ADD COLUMN backchannel_logout_session_required numeric NOT NULL DEFAULT 0;
