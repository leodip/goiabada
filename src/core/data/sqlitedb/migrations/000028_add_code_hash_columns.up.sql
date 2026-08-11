-- Look up a reset or activation link by an unsalted SHA-256 of its code (#112).
--
-- The links used to carry ?email=<address>&code=<code>. Go parses a query with
-- form-urlencoded rules, where '+' decodes to a space, so an address containing '+'
-- came back mangled and those users could neither reset a password nor activate an
-- account. The address leaves the link entirely rather than being escaped: the row is
-- now found by the hash of the code alone, and the code's alphabet is entirely
-- RFC 3986 unreserved, so nothing in either link ever needs percent-encoding again.
--
-- Added beside the existing encrypted columns rather than replacing them. Migrations
-- run forward-only at startup, so an older binary still serving traffic against the new
-- schema would SELECT a column that no longer existed.
--
-- NOT NULL DEFAULT '' rather than nullable: database/sql cannot scan NULL into a Go
-- string, so a nullable column would fail every read of a row written before this
-- migration. '' is the dormant value, meaning no code outstanding, and it is
-- unreachable from any supplied code because SHA-256 hex is always 64 characters.
--
-- The two index shapes differ deliberately. users.forgot_password_code_hash is '' on
-- most rows and two '' values are refused under a UNIQUE index on all four engines, so
-- it is a plain index. pre_registrations.verification_code_hash is UNIQUE, matching the
-- codes.code_hash precedent: after the DELETE below every row carries a real code hash.
--
-- The DELETE is what makes that true, and it is why this migration is not reversible.
-- Rows written before it carry no code hash, so the new lookup cannot find them and
-- they are unactivatable whatever we do here; leaving them in place would additionally
-- give two or more of them the same '' value, and CREATE UNIQUE INDEX would then abort
-- the migration at startup on any deployment holding more than one. A pre-registration
-- lives 5 minutes by construction, and anyone caught in the window registers again,
-- which is what the existing expired-link page already tells them to do. The down
-- migration drops the indexes and the columns but CANNOT restore the deleted rows: the
-- data loss is one-way.
DELETE FROM pre_registrations;

ALTER TABLE users ADD COLUMN forgot_password_code_hash TEXT NOT NULL DEFAULT '';
ALTER TABLE pre_registrations ADD COLUMN verification_code_hash TEXT NOT NULL DEFAULT '';

CREATE INDEX idx_users_forgot_password_code_hash ON users(forgot_password_code_hash);
CREATE UNIQUE INDEX idx_pre_reg_verification_code_hash ON pre_registrations(verification_code_hash);
