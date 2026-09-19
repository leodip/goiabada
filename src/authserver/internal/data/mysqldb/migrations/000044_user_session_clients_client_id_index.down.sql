-- Back to the name InnoDB gave the foreign key's index before #139 levelled it up.
ALTER TABLE `user_session_clients`
    RENAME INDEX `idx_user_session_clients_client_id` TO `fk_user_session_clients_client`;
