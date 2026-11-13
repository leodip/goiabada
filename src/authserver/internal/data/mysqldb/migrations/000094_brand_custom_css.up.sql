-- A brand's custom CSS (#816 decision 4). See the sqlite migration of the same number for why and
-- for the six questions.
--
-- The column inherits brands' case- and accent-sensitive collation (#283). It is a LONGTEXT, as
-- footer_links is; MySQL takes a default on a text column only as an expression, so its default
-- is ('').
ALTER TABLE `brands` ADD COLUMN `custom_css` longtext NOT NULL DEFAULT ('');
