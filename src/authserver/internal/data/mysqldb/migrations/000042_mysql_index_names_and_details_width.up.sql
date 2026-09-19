-- parity: mysql only. Both fixes correct a place where MySQL alone built something other
-- than what the other three engines built, found by #284's cross-engine comparison the
-- first time it ran over the four golden files. SQLite, PostgreSQL and SQL Server are
-- already in the state this brings MySQL to.

-- 1. Three foreign-key indexes are named after the constraint rather than after the column.
--
-- InnoDB requires an index over a foreign key's columns, so the initial migration declared
-- KEY `fk_codes_user`, KEY `fk_refresh_tokens_code` and KEY `fk_user_sessions_user` inline
-- to satisfy it. 000024 then created idx_codes_user_id, idx_refresh_tokens_code_id and
-- idx_user_sessions_user_id on SQLite, PostgreSQL and SQL Server, and skipped MySQL because
-- the index was already there under another name.
--
-- The indexes cover the same columns either way, so nothing about query planning changes.
-- What changes is that a later migration can now say DROP INDEX idx_codes_user_id on all
-- four engines: written today it succeeds on three and fails on MySQL alone, which is
-- exactly the failure decision 2 of #284 says a name comparison exists to catch.
--
-- RENAME INDEX is in-place metadata on InnoDB and is accepted for an index a foreign key
-- depends on, which DROP INDEX would not be.
ALTER TABLE `codes` RENAME INDEX `fk_codes_user` TO `idx_codes_user_id`;
ALTER TABLE `refresh_tokens` RENAME INDEX `fk_refresh_tokens_code` TO `idx_refresh_tokens_code_id`;
ALTER TABLE `user_sessions` RENAME INDEX `fk_user_sessions_user` TO `idx_user_sessions_user_id`;

-- 2. audit_logs.details is capped at 64 KiB on MySQL and unbounded on the other three.
--
-- 000018 declared it TEXT, whose ceiling is 65,535 bytes. The same column is TEXT on SQLite
-- and PostgreSQL and NVARCHAR(MAX) on SQL Server, none of which caps it anywhere near that.
-- details holds the JSON payload of an audit event, which is written by CreateAuditLog with
-- whatever the caller assembled, so the cap is reachable: a long request, a long list of
-- scopes or a long error string past 64 KiB is truncated under a non-strict sql_mode and
-- errors under the strict one MySQL 8 defaults to, and either way the audit record of a
-- security event is the thing that is lost.
--
-- LONGTEXT is MySQL's largest, 4 GiB, and it is what browser_sessions.data already uses for
-- the same reason. The collation, the NOT NULL and the default are restated because MODIFY
-- replaces the whole column definition and drops anything left out; the default has to stay
-- an expression, since MySQL refuses a literal default on a TEXT or LONGTEXT column with
-- ERROR 1101 (#282).
--
-- This one is not metadata-only: changing a column's type rebuilds the table with
-- ALGORITHM=COPY, and audit_logs is typically the largest table in a deployment.
ALTER TABLE `audit_logs`
    MODIFY `details` LONGTEXT COLLATE utf8mb4_0900_as_cs NOT NULL DEFAULT ('{}');
