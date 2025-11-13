ALTER TABLE settings
  ADD COLUMN session_authentication_key BLOB,
  ADD COLUMN session_encryption_key BLOB;
