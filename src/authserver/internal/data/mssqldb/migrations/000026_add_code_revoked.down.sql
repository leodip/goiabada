-- Constraint before column: see the up migration for why.
ALTER TABLE [codes] DROP CONSTRAINT [df_codes_revoked];
ALTER TABLE [codes] DROP COLUMN [revoked];
