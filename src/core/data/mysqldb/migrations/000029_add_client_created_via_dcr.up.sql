-- Self-registered clients require consent (#108). See the sqlite migration of the same
-- number for what the column means, why the backfill also sets consent_required, and
-- why the escape character is '!' rather than '\'.
ALTER TABLE `clients` ADD COLUMN `created_via_dcr` tinyint(1) NOT NULL DEFAULT 0;

UPDATE `clients` SET `created_via_dcr` = 1, `consent_required` = 1
 WHERE `client_identifier` LIKE 'dcr!_%' ESCAPE '!';
