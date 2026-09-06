-- Restores the two columns as 000001 declared them: BYTEA NOT NULL with no default, not the
-- nullable BYTEA this down used to add back.
--
-- Added WITH a default and then stripped of it, in two statements, because PostgreSQL refuses
-- to add a NOT NULL column to a populated table without one and the shape being restored
-- carries none. The empty value is all a down can put there: 000003's up dropped the columns
-- and their contents went with them (#268 decision 11).
ALTER TABLE settings
  ADD COLUMN session_authentication_key BYTEA NOT NULL DEFAULT ''::bytea,
  ADD COLUMN session_encryption_key BYTEA NOT NULL DEFAULT ''::bytea;

ALTER TABLE settings
  ALTER COLUMN session_authentication_key DROP DEFAULT,
  ALTER COLUMN session_encryption_key DROP DEFAULT;
