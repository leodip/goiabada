-- Every string column on this engine moves to utf8mb4_0900_as_cs, the case- and
-- accent-SENSITIVE collation, so `=` and every UNIQUE index over a string mean here what
-- they already mean on SQLite and PostgreSQL (#283).
--
-- Why it is a conformance fix and not a preference. RFC 6749 section 1.9 says "Unless
-- otherwise noted, all the protocol parameter names and values are case sensitive", and
-- section 2.2 notes no exception for client_id; section 3.3 says the same of scope, whose
-- two halves are Goiabada's resource and permission identifiers; OpenID Connect Core
-- section 2 says "The sub value is a case-sensitive string". Under utf8mb4_0900_ai_ci a
-- token request naming client_id=myapp resolves the client registered as MyApp, which
-- violates all three.
--
-- The direction is the safe one. Going from a folding collation to a non-folding one only
-- ever RELAXES uniqueness, so no existing row can fail this conversion. The down migration
-- is the direction that can fail, and it says so.
--
-- The database default goes first, so a column a LATER migration adds without spelling
-- COLLATE lands at the new collation rather than the old one. The name is omitted
-- deliberately: MySQL applies ALTER DATABASE with no name to the connection's default
-- database, and the database name is the operator's, not this file's. Measured on a
-- database pre-created at latin1_swedish_ci: this statement plus the per-table CONVERT
-- below repairs the database default, the table defaults, the existing columns, and both a
-- column and a table added afterwards, so a MySQL deployment an operator pre-created ends
-- up indistinguishable from one Goiabada created.
ALTER DATABASE CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_as_cs;

-- CONVERT TO CHARACTER SET rewrites every string column of the table and rebuilds its
-- indexes in one statement. Measured: it runs with a UNIQUE index in place and the index
-- survives and stays unique; ALGORITHM=INSTANT is refused (ERROR 1845) and INPLACE is
-- accepted, so the default algorithm is left to the server.
--
-- All 25 Goiabada tables, not only the ones holding an identity column. That is what makes
-- the rule mechanical: nobody has to decide whether the next column added is an identity
-- column, and it takes audit_logs, client_logos and user_profile_pictures with it, the
-- three tables built at utf8mb4_unicode_ci by 000018, 000014 and 000008 while the other 22
-- were built at utf8mb4_0900_ai_ci. That split folds trailing spaces where the other
-- collation does not, so it was a fourth string semantics inside one engine.
--
-- schema_migrations is deliberately absent. It is golang-migrate's own bookkeeping, it
-- holds no application value, and converting the table a migration is recorded in while
-- that migration runs is not something to find out about in production.
ALTER TABLE `audit_logs` CONVERT TO CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_as_cs;
ALTER TABLE `browser_sessions` CONVERT TO CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_as_cs;
ALTER TABLE `client_logos` CONVERT TO CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_as_cs;
ALTER TABLE `clients` CONVERT TO CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_as_cs;
ALTER TABLE `clients_permissions` CONVERT TO CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_as_cs;
ALTER TABLE `codes` CONVERT TO CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_as_cs;
ALTER TABLE `group_attributes` CONVERT TO CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_as_cs;
ALTER TABLE `groups` CONVERT TO CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_as_cs;
ALTER TABLE `groups_permissions` CONVERT TO CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_as_cs;
ALTER TABLE `key_pairs` CONVERT TO CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_as_cs;
ALTER TABLE `permissions` CONVERT TO CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_as_cs;
ALTER TABLE `pre_registrations` CONVERT TO CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_as_cs;
ALTER TABLE `redirect_uris` CONVERT TO CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_as_cs;
ALTER TABLE `refresh_tokens` CONVERT TO CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_as_cs;
ALTER TABLE `resources` CONVERT TO CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_as_cs;
ALTER TABLE `settings` CONVERT TO CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_as_cs;
ALTER TABLE `user_attributes` CONVERT TO CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_as_cs;
ALTER TABLE `user_consents` CONVERT TO CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_as_cs;
ALTER TABLE `user_profile_pictures` CONVERT TO CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_as_cs;
ALTER TABLE `user_session_clients` CONVERT TO CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_as_cs;
ALTER TABLE `user_sessions` CONVERT TO CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_as_cs;
ALTER TABLE `users` CONVERT TO CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_as_cs;
ALTER TABLE `users_groups` CONVERT TO CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_as_cs;
ALTER TABLE `users_permissions` CONVERT TO CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_as_cs;
ALTER TABLE `web_origins` CONVERT TO CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_as_cs;
