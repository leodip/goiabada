-- A session records when its password was entered, apart from auth_time (#542 review).
--
-- auth_time is when the user last authenticated: the password's time, or a one-time code's when the
-- code was entered after it, as a step-up does. Removing a user's authenticator lowers each of
-- their sessions to what the password alone reached, amr ["pwd"], and auth_time has to come down
-- with it to the time the password was entered, or a token would say a password was entered when
-- only a code was. Nothing recorded that time until now.
--
-- It can't be recovered for a session already stored: for every session that stepped up, auth_time
-- is the code's. So every session is ended and its user signs in again. Each row's
-- user_session_clients go with it (ON DELETE CASCADE); refresh tokens bound to a session stop, as
-- they do when it expires, and offline ones are kept. Emptying the table first is also what lets
-- the column be added NOT NULL with no default, on SQLite as on the other three engines.
DELETE FROM user_sessions;

ALTER TABLE user_sessions ADD COLUMN password_auth_time DATETIME NOT NULL;
