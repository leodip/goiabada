-- Revert: Remove user_id and client_id columns, make code_id NOT NULL again

-- First delete any ROPC tokens (those with NULL code_id)
DELETE FROM public.refresh_tokens WHERE code_id IS NULL;

-- Drop indexes
DROP INDEX IF EXISTS idx_refresh_tokens_user_id;
DROP INDEX IF EXISTS idx_refresh_tokens_client_id;

-- Drop foreign key constraints
ALTER TABLE public.refresh_tokens DROP CONSTRAINT IF EXISTS fk_refresh_tokens_user;
ALTER TABLE public.refresh_tokens DROP CONSTRAINT IF EXISTS fk_refresh_tokens_client;

-- Make code_id NOT NULL again
ALTER TABLE public.refresh_tokens ALTER COLUMN code_id SET NOT NULL;

-- Drop columns
ALTER TABLE public.refresh_tokens DROP COLUMN IF EXISTS user_id;
ALTER TABLE public.refresh_tokens DROP COLUMN IF EXISTS client_id;
