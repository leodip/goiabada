-- A user's recovery codes (#257 decisions 2 and 3): the set of ten single-use codes that comes with
-- every new authenticator, one row per code. A code is stored as its SHA-256 in lowercase hex and
-- never in any other form: at 120 bits NIST SP 800-63B-4 section 3.1.2.2 asks only that a look-up
-- secret be stored hashed with an approved function, so checking one is one indexed lookup. The
-- codes are hashed, never encrypted, so rotating the AES key does not touch them.
--
-- The six questions (reference/migrations.md 6): (1) all four engines. (2) code_hash is pinned
-- case-sensitive and is 64 wide, as codes.code_hash is. (3) The lookups compare the user's id and
-- the hash with =. (4) A code appears once in a user's set: the pair is unique. (5) No existing row
-- changes meaning, and nothing is backfilled: users who already have an authenticator have no codes
-- until they ask for a set. (6) Each schema.golden gains the table.
--
-- A used code is kept, with used_at stamped, until its set is replaced or the authenticator is
-- removed; using one is a conditional write that stamps used_at only while it is empty. The rows go
-- with their user, as every table hanging off a user does. The unique index leads with user_id, so
-- it serves the user's whole set too: the count, the replacement and the deletion.
CREATE TABLE user_recovery_codes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    code_hash TEXT NOT NULL,
    created_at DATETIME NOT NULL,
    used_at DATETIME NULL,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);
CREATE UNIQUE INDEX idx_user_recovery_codes_user_code_hash ON user_recovery_codes(user_id, code_hash);
