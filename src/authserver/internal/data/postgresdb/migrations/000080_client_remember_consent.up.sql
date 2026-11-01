-- A client's Remember consent setting (#711 decisions 1, 4 and 7). See the sqlite migration of the
-- same number for what the column means, why it defaults to off and why the backfill turns it on
-- for every confidential client alone.
ALTER TABLE clients ADD COLUMN remember_consent boolean NOT NULL DEFAULT false;

UPDATE clients SET remember_consent = true WHERE is_public = false;
