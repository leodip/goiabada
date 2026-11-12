-- Reverses migration 000093 (#815). See the sqlite migration for what is lost.
ALTER TABLE [brands] DROP COLUMN [palette];
