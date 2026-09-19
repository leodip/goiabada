-- Durable session termination (#129). See the sqlite migration of the same number
-- for what the column means, why the marker sits on the code, and why existing rows
-- land at false.
--
-- The default constraint is NAMED deliberately, for the reason 000024 gives: SQL
-- Server refuses to drop a column while a default constraint depends on it, so the
-- down migration has to drop the constraint by name first.
ALTER TABLE [codes] ADD [revoked] BIT NOT NULL
    CONSTRAINT [df_codes_revoked] DEFAULT 0;
