-- Index the rotation family identifier (#128). See the sqlite migration of the same
-- number for what containment queries and why the index must not be UNIQUE.
--
-- Nothing covers this column here already: InnoDB indexes foreign key columns
-- automatically and the initial migration declares KEY fk_refresh_tokens_code inline,
-- but first_refresh_token_jti has no foreign key.
CREATE INDEX `idx_refresh_tokens_first_refresh_token_jti`
    ON `refresh_tokens`(`first_refresh_token_jti`);
