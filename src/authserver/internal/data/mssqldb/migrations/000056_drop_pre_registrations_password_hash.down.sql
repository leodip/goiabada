-- Migration 000056 down: re-add pre_registrations.password_hash with the type, collation and
-- spelled nullability 000055 left it in. The shape comes back, never the values: the column is
-- added with a named empty-string default so the rows it finds can satisfy NOT NULL, and the
-- constraint is then dropped by that name, because 000055's column had none and the up migration
-- could not drop the column while a default constraint depends on it.
ALTER TABLE [pre_registrations] ADD [password_hash] NVARCHAR(64)
    COLLATE Latin1_General_100_CS_AS_KS_WS_SC_UTF8 NOT NULL
    CONSTRAINT [df_pre_registrations_password_hash] DEFAULT '';
ALTER TABLE [pre_registrations] DROP CONSTRAINT [df_pre_registrations_password_hash];
