-- The token_endpoint_auth_method a client registered through dynamic client registration (#708
-- decision 3). See the sqlite migration of the same number for what the column holds and why
-- nothing is backfilled.
ALTER TABLE clients ADD COLUMN token_endpoint_auth_method varchar(64) NOT NULL DEFAULT '';
