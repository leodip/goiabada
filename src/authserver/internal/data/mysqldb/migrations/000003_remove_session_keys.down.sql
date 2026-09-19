-- Restores the two columns as 000001 declared them: longblob NOT NULL, not the nullable BLOB
-- this down used to add back. Both halves mattered; the type was wrong too.
--
-- No DEFAULT, because 000001 gives them none. MySQL fills the existing rows of an added
-- NOT NULL column with the type's implicit default, an empty blob here, which is all a down
-- can do: 000003's up dropped the columns and their contents went with them (#268 decision 11).
ALTER TABLE settings
  ADD COLUMN session_authentication_key LONGBLOB NOT NULL,
  ADD COLUMN session_encryption_key LONGBLOB NOT NULL;
