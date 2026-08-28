-- Back to the folding collations, which is where MySQL stood before #283.
--
-- THIS DIRECTION IS ALLOWED TO FAIL, and on a deployment that has used the case-sensitive
-- schema it usually will. utf8mb4_0900_as_cs permits `MyApp` and `myapp` to coexist under
-- idx_client_identifier; utf8mb4_0900_ai_ci does not, so the conversion is refused with
-- ERROR 1062 naming the first offending value. That leaves schema_migrations DIRTY, which
-- blocks every later run until an operator clears it by hand, and the only way through is
-- to resolve the duplicate rows first. Nothing here can recover automatically: the
-- information about which of two rows the operator wants is not in the database.
--
-- What it also cannot recover: a collation an operator pre-created the database with. The
-- up migration overwrote the database default and every table with it, and the original is
-- recorded nowhere.
--
-- Each table goes back to ITS OWN prior collation rather than to one value, because the
-- schema was not uniform before: audit_logs, client_logos and user_profile_pictures were
-- built at utf8mb4_unicode_ci by 000018, 000014 and 000008, and the other 22 at
-- utf8mb4_0900_ai_ci. Restoring all 25 to the majority collation would make down/up stop
-- being a round trip on those three, which is precisely what the version table would then
-- be claiming falsely. Both collations are named outright; neither is read from the
-- database default, which this file restores in the same breath and which a database
-- Goiabada created after #283 would otherwise leave sitting at the new target.
ALTER DATABASE CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci;

ALTER TABLE `audit_logs` CONVERT TO CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
ALTER TABLE `client_logos` CONVERT TO CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
ALTER TABLE `user_profile_pictures` CONVERT TO CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

ALTER TABLE `browser_sessions` CONVERT TO CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci;
ALTER TABLE `clients` CONVERT TO CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci;
ALTER TABLE `clients_permissions` CONVERT TO CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci;
ALTER TABLE `codes` CONVERT TO CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci;
ALTER TABLE `group_attributes` CONVERT TO CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci;
ALTER TABLE `groups` CONVERT TO CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci;
ALTER TABLE `groups_permissions` CONVERT TO CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci;
ALTER TABLE `key_pairs` CONVERT TO CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci;
ALTER TABLE `permissions` CONVERT TO CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci;
ALTER TABLE `pre_registrations` CONVERT TO CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci;
ALTER TABLE `redirect_uris` CONVERT TO CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci;
ALTER TABLE `refresh_tokens` CONVERT TO CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci;
ALTER TABLE `resources` CONVERT TO CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci;
ALTER TABLE `settings` CONVERT TO CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci;
ALTER TABLE `user_attributes` CONVERT TO CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci;
ALTER TABLE `user_consents` CONVERT TO CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci;
ALTER TABLE `user_session_clients` CONVERT TO CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci;
ALTER TABLE `user_sessions` CONVERT TO CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci;
ALTER TABLE `users` CONVERT TO CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci;
ALTER TABLE `users_groups` CONVERT TO CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci;
ALTER TABLE `users_permissions` CONVERT TO CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci;
ALTER TABLE `web_origins` CONVERT TO CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci;
