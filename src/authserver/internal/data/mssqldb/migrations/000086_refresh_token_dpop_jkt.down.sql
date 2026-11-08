-- Migration 000086 down: see the sqlite migration of the same number. No constraint to drop first,
-- because the up migration gave the column no default.
ALTER TABLE [refresh_tokens] DROP COLUMN [dpop_jkt];
