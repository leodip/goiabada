-- A brand's support contact and footer links (#814 decision 8). See the sqlite migration of the
-- same number for why and for the six questions. PostgreSQL compares strings byte-wise, so no
-- column needs a collation pin.
ALTER TABLE brands ADD COLUMN support_email VARCHAR(254) NOT NULL DEFAULT '';
ALTER TABLE brands ADD COLUMN support_url VARCHAR(256) NOT NULL DEFAULT '';
ALTER TABLE brands ADD COLUMN support_phone VARCHAR(16) NOT NULL DEFAULT '';
ALTER TABLE brands ADD COLUMN footer_links TEXT NOT NULL DEFAULT '[]';
