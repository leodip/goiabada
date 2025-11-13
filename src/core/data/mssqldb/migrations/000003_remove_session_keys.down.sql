ALTER TABLE settings
  ADD session_authentication_key VARBINARY(MAX),
  ADD session_encryption_key VARBINARY(MAX);
