-- Restore the cascade 000011 declared on both constraints.

ALTER TABLE `refresh_tokens` DROP FOREIGN KEY `fk_refresh_tokens_user`;
ALTER TABLE `refresh_tokens` DROP FOREIGN KEY `fk_refresh_tokens_client`;

ALTER TABLE `refresh_tokens` ADD CONSTRAINT `fk_refresh_tokens_user`
    FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE CASCADE;
ALTER TABLE `refresh_tokens` ADD CONSTRAINT `fk_refresh_tokens_client`
    FOREIGN KEY (`client_id`) REFERENCES `clients` (`id`) ON DELETE CASCADE;
