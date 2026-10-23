-- parity: mysql, postgres and mssql only. SQLite stores all four columns as TEXT, which has no width.
--
-- Widens the four columns an email address is stored in from 64 to 254 characters (#632):
-- users.email, pre_registrations.email, settings.smtp_from_email and settings.smtp_username. See
-- the MySQL migration of the same number for why each column, and why 254.
--
-- Raising a VARCHAR's limit is a catalog change with no table rewrite, including under the unique
-- index idx_email and under idx_pre_reg_email, whose widened keys stay far inside the 2704 bytes a
-- B-tree entry allows. ALTER COLUMN ... TYPE keeps the column's nullability and its collation.
ALTER TABLE users ALTER COLUMN email TYPE VARCHAR(254);

ALTER TABLE pre_registrations ALTER COLUMN email TYPE VARCHAR(254);

ALTER TABLE settings ALTER COLUMN smtp_from_email TYPE VARCHAR(254);

ALTER TABLE settings ALTER COLUMN smtp_username TYPE VARCHAR(254);
