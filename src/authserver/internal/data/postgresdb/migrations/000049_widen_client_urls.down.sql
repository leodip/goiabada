-- Back to the width the three columns carried before #428.
--
-- Each statement narrows the column to 256 characters, so a row that grew past that is refused
-- with SQLSTATE 22001 and the file fails. That is what restoring the previous shape means here.
ALTER TABLE redirect_uris ALTER COLUMN uri TYPE VARCHAR(256);

ALTER TABLE codes ALTER COLUMN redirect_uri TYPE VARCHAR(256);

ALTER TABLE web_origins ALTER COLUMN origin TYPE VARCHAR(256);
