-- A session's device identifier and the per-user session cap (#564 decision 11).
--
-- user_sessions.device_id names the browser that started the session: the SHA-256, in hex, of the
-- value of the auth server's device cookie, and never the value itself, so a database read hands out
-- nothing a browser could present. A sign-in that starts a new session ends the user's other
-- sessions from the same browser by this column, where it compared user_agent and ip_address (000046),
-- which two windows, two profiles and two machines behind one router all share.
--
-- settings.max_user_sessions_per_user is how many sessions one user may hold, 0 meaning no limit.
-- Past it, a sign-in ends the user's expired and then least recently used sessions.
--
-- Both columns carry a default, and that is what a rolling upgrade rests on: the previous release,
-- still serving while this one migrates, goes on inserting sessions that name no device_id and saving
-- settings that name no cap. Its sessions read '', as every session stored before the upgrade does,
-- and an empty identifier matches nothing, so those sessions expire on their own by idle timeout or
-- max lifetime; nothing is backfilled, since the cookie was never stored. Its saves leave the cap as
-- stored. An existing installation's cap is 20, the value a new one is seeded with, rather than no
-- limit: 20 is far above what one person uses, so it catches only a pile-up.
--
-- No index: the sweep and the cap read the user's sessions by user_id, as the sweep did before.
ALTER TABLE user_sessions ADD COLUMN device_id TEXT NOT NULL DEFAULT '';

ALTER TABLE settings ADD COLUMN max_user_sessions_per_user INTEGER NOT NULL DEFAULT 20;
