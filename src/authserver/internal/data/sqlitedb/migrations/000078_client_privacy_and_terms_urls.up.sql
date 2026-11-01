-- A client's own privacy policy URL and terms of service URL (#622 decision 12).
--
-- clients.privacy_policy_url and clients.terms_of_service_url hold the addresses of the app's own
-- privacy policy and terms of service, which the consent screen links whenever they are set, as
-- RFC 7591 section 2 says the server SHOULD for policy_uri and tos_uri. An administrator sets them on
-- the client's Settings tab or through the admin API's settings update, validated like website_url:
-- optional, http or https, at most 256 characters. Dynamic client registration stores a policy_uri or
-- tos_uri only when it has the scheme and host of one of the client's redirect URIs.
--
-- Every existing client starts with neither, through the columns' default: the auth server ignored
-- both registration fields until now, so there is nothing to backfill. The down migration drops both
-- columns, and every URL set since with them.
ALTER TABLE clients ADD COLUMN privacy_policy_url TEXT NOT NULL DEFAULT '';
ALTER TABLE clients ADD COLUMN terms_of_service_url TEXT NOT NULL DEFAULT '';
