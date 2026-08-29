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
-- Divergence 3, the PKCE columns, needs no file here: MySQL has had
-- codes.code_challenge and code_challenge_method nullable since its own 000007. SQLite
-- carries that half of 000039.
--
-- InnoDB creates an index for every foreign key, so dropping a constraint could have
-- taken an index with it and undone 000036's work on this engine. Measured: both
-- idx_refresh_tokens_user_id and idx_refresh_tokens_client_id survive the swap, and
-- information_schema.REFERENTIAL_CONSTRAINTS.DELETE_RULE then reads NO ACTION.

ALTER TABLE `refresh_tokens` DROP FOREIGN KEY `fk_refresh_tokens_user`;
ALTER TABLE `refresh_tokens` DROP FOREIGN KEY `fk_refresh_tokens_client`;

ALTER TABLE `refresh_tokens` ADD CONSTRAINT `fk_refresh_tokens_user`
    FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE NO ACTION;
ALTER TABLE `refresh_tokens` ADD CONSTRAINT `fk_refresh_tokens_client`
    FOREIGN KEY (`client_id`) REFERENCES `clients` (`id`) ON DELETE NO ACTION;
