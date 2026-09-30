-- Back to the width the five columns carried before #437.
--
-- Each statement narrows the column to 512 characters, so a row that grew past that is refused
-- with SQLSTATE 22001 and the file fails. That is what restoring the previous shape means here.
ALTER TABLE codes
    ALTER COLUMN state TYPE VARCHAR(512),
    ALTER COLUMN nonce TYPE VARCHAR(512),
    ALTER COLUMN scope TYPE VARCHAR(512);

ALTER TABLE refresh_tokens ALTER COLUMN scope TYPE VARCHAR(512);

ALTER TABLE user_consents ALTER COLUMN scope TYPE VARCHAR(512);
