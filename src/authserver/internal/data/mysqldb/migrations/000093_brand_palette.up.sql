-- A brand's custom palette (#815 decision 3). See the sqlite migration of the same number for why
-- and for the six questions.
--
-- The column inherits brands' case- and accent-sensitive collation (#283). It is a LONGTEXT, as
-- footer_links is, and nullable with no default.
ALTER TABLE `brands` ADD COLUMN `palette` longtext NULL;
