-- Per-user OTP configuration generation, replacing user_sessions.level2_auth_config_has_changed
-- (#242).
--
-- users.otp_config_generation is the authoritative counter. It advances by one every time an
-- authenticator is established or removed, and never otherwise. user_sessions.otp_config_generation
-- records the value that session last satisfied, and a session owes a level 2 re-prompt when the two
-- differ. The whole reason for a counter rather than the boolean it replaces is that reading it is
-- not writing it: the two readers compare two integers and write nothing, so a ceremony a visitor
-- abandons at the OTP prompt no longer spends the re-prompt it was owed. Being per user, one
-- statement covers every session of that user, which the boolean never did.
--
-- The seed hands the old column's obligations to the new one and widens them, in one UPDATE with two
-- clauses that are both load-bearing:
--
--   level2_auth_config_has_changed = 1 preserves what the old writers had already flagged. Those
--   sessions belong overwhelmingly to users who have just DISABLED an authenticator, so their
--   otp_enabled is now false and the second clause alone would discharge exactly the obligations
--   this clause exists to hand over.
--
--   user_id IN (SELECT id FROM users WHERE otp_enabled = 1) covers the bypass the old writer left
--   open. It wrote only the row named by the caller's own sid claim, so a session authenticated at
--   level2_optional with amr ["pwd"] while the user had no authenticator was never flagged when the
--   user later enabled OTP somewhere else. Without this clause that session keeps obtaining tokens
--   stamped acr: urn:goiabada:level2_optional with amr: ["pwd"] for a user who now has an
--   authenticator, which is not the class OIDC Core section 2 says the authentication performed
--   satisfied. Users with no authenticator are untouched: no false level 2 assertion is possible for
--   them in either direction.
--
-- -1 rather than any non-negative value: the counter starts at 0 and only rises, and the readers
-- compare with != rather than <, so -1 never matches and each seeded session is re-prompted exactly
-- once and then promoted like any other.
--
-- The drop is last, and it is what makes this migration and models.UserSession losing the field one
-- commit: with the field kept and the column gone every session query names a column that is not
-- there, and with the field gone and the column kept every insert omits a NOT NULL column with no
-- default on three engines. Nothing indexes or constrains the column on any engine, which is
-- SQLite's requirement before DROP COLUMN.
--
-- The down migration restores level2_auth_config_has_changed NOT NULL DEFAULT 0, where the original
-- had no default on three engines, because existing rows need a value. It does not restore which
-- sessions were flagged: only the -1 seed is recoverable and the rest is not. 000023's down
-- recreates http_sessions without its rows for the same reason.
ALTER TABLE users ADD COLUMN otp_config_generation INTEGER NOT NULL DEFAULT 0;
ALTER TABLE user_sessions ADD COLUMN otp_config_generation INTEGER NOT NULL DEFAULT 0;

UPDATE user_sessions SET otp_config_generation = -1
 WHERE level2_auth_config_has_changed = 1
    OR user_id IN (SELECT id FROM users WHERE otp_enabled = 1);

ALTER TABLE user_sessions DROP COLUMN level2_auth_config_has_changed;
