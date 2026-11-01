-- A client's Remember consent setting (#711 decisions 1, 4 and 7). See the sqlite migration of the
-- same number for what the column means, why it defaults to off and why the backfill turns it on
-- for every confidential client alone.
ALTER TABLE `clients` ADD COLUMN `remember_consent` tinyint(1) NOT NULL DEFAULT 0;

UPDATE `clients` SET `remember_consent` = 1 WHERE `is_public` = 0;
