-- Migration 000056 down: re-add pre_registrations.password_hash with the shape 000055 left it in,
-- TEXT NOT NULL with no default. The shape comes back, never the values: every row reads ''.
--
-- A rebuild rather than an ADD COLUMN. SQLite adds a NOT NULL column only with a default, and it
-- cannot drop a default afterwards, so an ADD COLUMN would leave password_hash with a DEFAULT ''
-- that 000055 never had. The rows are copied with '' in the restored column, which is the
-- empty-string default the other three engines add the column with and then drop.
--
-- Safe for the same reason as 000043's rebuild: nothing holds a foreign key onto
-- pre_registrations. Both indexes are recreated because DROP TABLE takes them with it.
CREATE TABLE pre_registrations_old (
  `id` integer PRIMARY KEY AUTOINCREMENT,
  created_at DATETIME,
  updated_at DATETIME,
  email TEXT,
  password_hash TEXT NOT NULL,
  verification_code_encrypted BLOB,
  verification_code_issued_at DATETIME,
  verification_code_hash TEXT NOT NULL DEFAULT ''
);
INSERT INTO pre_registrations_old (id, created_at, updated_at, email, password_hash,
    verification_code_encrypted, verification_code_issued_at, verification_code_hash)
SELECT id, created_at, updated_at, email, '',
    verification_code_encrypted, verification_code_issued_at, verification_code_hash
FROM pre_registrations;
DROP TABLE pre_registrations;
ALTER TABLE pre_registrations_old RENAME TO pre_registrations;
CREATE INDEX `idx_pre_reg_email` ON `pre_registrations`(`email`);
CREATE UNIQUE INDEX idx_pre_reg_verification_code_hash ON pre_registrations(verification_code_hash);
