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
-- they do when it expires, and offline ones are kept.
--
-- Every code not yet redeemed is revoked with them, as ending a session revokes the codes it
-- authorized. A code issued just before the upgrade would otherwise be consumed at redemption and
-- then fail, since minting its session-bound refresh token reads a session that is gone; revoked,
-- it is refused with invalid_grant before anything is consumed, and the client signs in again.
--
-- Except a redemption already under way. During a rolling upgrade the previous release can claim a
-- code after the sessions are deleted and before this revokes it. A code granted offline_access then
-- redeems: its refresh token is offline and reads no session. Any other code's mint fails on the
-- missing session, as a redemption does when its session is ended in the middle: the code is spent,
-- the token endpoint answers 500 server_error, and the app has to start a new sign-in. Nothing
-- orders a redemption against this, nor against an ending, and for a code that lives 60 seconds
-- that failure is the accepted price (IssueAuthorizationCodeGrant).
--
-- Emptying the table first is what lets SQLite add the column NOT NULL with no default. SQLite is
-- one process, so nothing can insert between the two. The other three engines order it the other
-- way for a rolling upgrade, as the mysql migration of the same number explains.
DELETE FROM user_sessions;

ALTER TABLE user_sessions ADD COLUMN password_auth_time DATETIME NOT NULL;

UPDATE codes SET revoked = 1 WHERE used = 0 AND revoked = 0;
