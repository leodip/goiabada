-- Restore the cascade 000011 declared on both constraints.

ALTER TABLE public.refresh_tokens DROP CONSTRAINT fk_refresh_tokens_user;
ALTER TABLE public.refresh_tokens DROP CONSTRAINT fk_refresh_tokens_client;

ALTER TABLE public.refresh_tokens
    ADD CONSTRAINT fk_refresh_tokens_user
    FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;

ALTER TABLE public.refresh_tokens
    ADD CONSTRAINT fk_refresh_tokens_client
    FOREIGN KEY (client_id) REFERENCES public.clients(id) ON DELETE CASCADE;
