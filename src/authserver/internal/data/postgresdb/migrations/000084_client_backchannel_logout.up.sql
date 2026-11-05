-- A client's back-channel logout settings (#784 decision 14). See the sqlite migration of the same
-- number for what the columns hold and why nothing is backfilled.
--
-- The URI's width is a redirect URI's, 2048, the most the admin API and dynamic registration take.
ALTER TABLE clients ADD COLUMN backchannel_logout_uri varchar(2048) NOT NULL DEFAULT '';
ALTER TABLE clients ADD COLUMN backchannel_logout_session_required boolean NOT NULL DEFAULT false;
