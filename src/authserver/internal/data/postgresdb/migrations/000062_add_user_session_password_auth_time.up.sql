-- A session records when its password was entered, apart from auth_time (#542 review). See the
-- sqlite migration of the same number for why every stored session is ended first.
DELETE FROM user_sessions;

ALTER TABLE user_sessions ADD COLUMN password_auth_time timestamp(6) without time zone NOT NULL;
