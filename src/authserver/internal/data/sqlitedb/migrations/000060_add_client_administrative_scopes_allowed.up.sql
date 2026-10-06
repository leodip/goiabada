-- A client's allowance to request the administrative authserver scopes (#499 decisions 3 and 8).
--
-- administrative_scopes_allowed is the stored half of the rule the server applies before it lets a
-- client obtain manage, admin-read, manage-users, manage-clients, manage-settings or
-- browser-sessions on a user's behalf: the admin console's client, by its built-in identifier, or
-- a client whose column says yes (record.Client.MayRequestAdministrativeScopes). Before it, any
-- client with the authorization code flow and consent off could be handed a signed-in
-- administrator's full Admin API authority by sending them one link.
--
-- Every existing client starts not allowed, through the column's default, and the backfill allows
-- the admin console's client alone. That is deliberate, and it is the whole of the upgrade's
-- effect: a deployment running another client that legitimately requests one of these scopes is
-- refused until an operator switches that client's allowance on. Allowing every client holding a
-- stored consent or a live refresh token with such a scope was rejected, because that evidence
-- cannot tell a legitimate tool from a client that already used the hole, and it misses the
-- consent-off clients entirely; allowing every client leaves the deployed attack surface open.
--
-- The admin console's client is allowed by the server whatever this column holds, so the backfill
-- is not what keeps administrators signing in. It is what makes the row, the API's answer and the
-- console's switch agree with what the server does. The match is the exact identifier: the column
-- compares case-sensitively on all four engines since 000040.
--
-- The down migration drops the column, and with it every allowance an operator switched on since.
ALTER TABLE clients ADD COLUMN administrative_scopes_allowed numeric NOT NULL DEFAULT 0;

UPDATE clients SET administrative_scopes_allowed = 1
 WHERE client_identifier = 'admin-console-client';
