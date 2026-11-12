-- A brand's support contact and footer links (#814 decision 8). See the sqlite migration of the
-- same number for why and for the six questions.
--
-- The columns inherit brands' case- and accent-sensitive collation (#283). footer_links is a
-- LONGTEXT, as audit_logs.details is; MySQL takes a default on a text column only as an
-- expression, so its default is ('[]'), as details' is ('{}').
ALTER TABLE `brands` ADD COLUMN `support_email` varchar(254) NOT NULL DEFAULT '';
ALTER TABLE `brands` ADD COLUMN `support_url` varchar(256) NOT NULL DEFAULT '';
ALTER TABLE `brands` ADD COLUMN `support_phone` varchar(16) NOT NULL DEFAULT '';
ALTER TABLE `brands` ADD COLUMN `footer_links` longtext NOT NULL DEFAULT ('[]');
