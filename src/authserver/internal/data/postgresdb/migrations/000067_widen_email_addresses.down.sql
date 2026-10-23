-- Back to the width the four columns carried before #632.
--
-- Each statement narrows the column to 64 characters, so a stored value that grew past that is
-- refused with SQLSTATE 22001 and the file fails, all of it, with the value whole rather than cut
-- to an address that is no longer the person's. That is what restoring the previous shape means
-- here. The narrowing rewrites the table and rebuilds idx_email and idx_pre_reg_email with it.
ALTER TABLE users ALTER COLUMN email TYPE VARCHAR(64);

ALTER TABLE pre_registrations ALTER COLUMN email TYPE VARCHAR(64);

ALTER TABLE settings ALTER COLUMN smtp_from_email TYPE VARCHAR(64);

ALTER TABLE settings ALTER COLUMN smtp_username TYPE VARCHAR(64);
