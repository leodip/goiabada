-- Restores the two columns as 000001 declared them: VARBINARY(MAX) NOT NULL with no default
-- constraint, not the nullable VARBINARY(MAX) this down used to add back.
--
-- Added WITH a default and then stripped of it, because SQL Server refuses to add a NOT NULL
-- column to a populated table without one and the shape being restored carries none. The
-- defaults are NAMED so these two statements can drop them: an unnamed one gets a generated
-- per-database name and would have to be hunted for in sys.default_constraints, which is the
-- same trap 000004's and 000017's downs fall into. The empty value is all a down can put
-- there: 000003's up dropped the columns and their contents went with them (#268 decision 11).
ALTER TABLE settings
  ADD session_authentication_key VARBINARY(MAX) NOT NULL
        CONSTRAINT df_settings_session_authentication_key DEFAULT 0x,
      session_encryption_key VARBINARY(MAX) NOT NULL
        CONSTRAINT df_settings_session_encryption_key DEFAULT 0x;

ALTER TABLE settings DROP CONSTRAINT df_settings_session_authentication_key;
ALTER TABLE settings DROP CONSTRAINT df_settings_session_encryption_key;
