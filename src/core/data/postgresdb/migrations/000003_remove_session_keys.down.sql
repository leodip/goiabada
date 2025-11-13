ALTER TABLE settings
  ADD COLUMN session_authentication_key BYTEA,
  ADD COLUMN session_encryption_key BYTEA;
