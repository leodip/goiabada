-- Migration 000088 down: see the sqlite migration of the same number. No constraint to drop first,
-- because the up migration gave the column no default.
ALTER TABLE [codes] DROP COLUMN [dpop_jkt];
