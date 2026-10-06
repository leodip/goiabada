-- A client's allowance to request the administrative authserver scopes (#499 decisions 3 and 8).
-- See the sqlite migration of the same number for what the column means and why the backfill
-- allows the admin console's client and no other.
ALTER TABLE clients ADD COLUMN administrative_scopes_allowed boolean NOT NULL DEFAULT false;

UPDATE clients SET administrative_scopes_allowed = true
 WHERE client_identifier = 'admin-console-client';
