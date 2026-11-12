-- A brand's support contact and footer links (#814 decision 8): brands gains three text columns
-- for the contact and one holding the whole list of footer links as JSON text.
--
-- The six questions a migration answers: (1) all four engines. (2) The contact values and the
-- links are validated text: an address, an https: URL, a "+" and digits, and the JSON the data
-- layer writes; they are pinned case-sensitive on MySQL and SQL Server, as every string column is.
-- (3) Nothing compares them: the links are read and written whole with their brand and never
-- looked up by a URL or a label, so no index. (4) No key: nothing refers to them. (5) Every
-- existing brand has an empty contact and no links, through the columns' defaults: '' for each
-- contact value and [], the empty list, for the links. (6) Each schema.golden gains the four
-- columns.
--
-- The widths are the admin API's bounds: 254 characters for the address, as every account address
-- has; 256 for the URL, as a client's website URL has; 16 for a "+" and up to 15 digits. The links
-- are unbounded text, as audit_logs.details is: the API bounds the list, not the column.
--
-- The previous release never reads brands, so a replica of it still serving during a rolling
-- upgrade keeps working. The down migration drops the four columns and every value in them.
ALTER TABLE brands ADD COLUMN support_email TEXT NOT NULL DEFAULT '';
ALTER TABLE brands ADD COLUMN support_url TEXT NOT NULL DEFAULT '';
ALTER TABLE brands ADD COLUMN support_phone TEXT NOT NULL DEFAULT '';
ALTER TABLE brands ADD COLUMN footer_links TEXT NOT NULL DEFAULT '[]';
