-- parity: mysql, postgres and sqlite only. SQL Server is the engine the other three are
-- converging on and needs no file: fk_refresh_tokens_user and fk_refresh_tokens_client have been
-- ON DELETE NO ACTION there since its 000011, and codes.code_challenge and code_challenge_method
-- have been nullable since its own 000007.
--
-- Issue #282 divergence 5: refresh_tokens.user_id and client_id come down to
-- ON DELETE NO ACTION to match SQL Server, which refuses the cascade outright
-- (Msg 1785: users <- codes <- refresh_tokens(code_id) alongside
-- users <- refresh_tokens(user_id) is a multiple cascade path). Parity is only reachable
-- downward, and it is unobservable: DeleteUser and DeleteClient are the only statements
-- that delete a user or a client row and both clear that row's refresh tokens first.
--
-- Divergence 3, the PKCE columns, needs no file here: PostgreSQL has had
-- codes.code_challenge and code_challenge_method nullable since its own 000007. SQLite
-- carries that half of 000039.
--
-- Measured alongside MySQL: idx_refresh_tokens_user_id and idx_refresh_tokens_client_id
-- both survive the swap, and pg_constraint.confdeltype then reads 'a'.

ALTER TABLE public.refresh_tokens DROP CONSTRAINT fk_refresh_tokens_user;
ALTER TABLE public.refresh_tokens DROP CONSTRAINT fk_refresh_tokens_client;

ALTER TABLE public.refresh_tokens
    ADD CONSTRAINT fk_refresh_tokens_user
    FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE NO ACTION;

ALTER TABLE public.refresh_tokens
    ADD CONSTRAINT fk_refresh_tokens_client
    FOREIGN KEY (client_id) REFERENCES public.clients(id) ON DELETE NO ACTION;
