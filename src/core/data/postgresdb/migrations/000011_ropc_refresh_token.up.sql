-- Add user_id and client_id columns to refresh_tokens for ROPC flow
-- These allow refresh tokens to be created without a Code entity

-- Add new columns
ALTER TABLE public.refresh_tokens ADD COLUMN user_id bigint NULL;
ALTER TABLE public.refresh_tokens ADD COLUMN client_id bigint NULL;

-- Make code_id nullable
ALTER TABLE public.refresh_tokens ALTER COLUMN code_id DROP NOT NULL;

-- Add foreign key constraints
ALTER TABLE public.refresh_tokens
    ADD CONSTRAINT fk_refresh_tokens_user
    FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;

ALTER TABLE public.refresh_tokens
    ADD CONSTRAINT fk_refresh_tokens_client
    FOREIGN KEY (client_id) REFERENCES public.clients(id) ON DELETE CASCADE;

-- Add indexes for the new foreign keys
CREATE INDEX idx_refresh_tokens_user_id ON public.refresh_tokens(user_id);
CREATE INDEX idx_refresh_tokens_client_id ON public.refresh_tokens(client_id);
