-- The raw User-Agent header on the session row (#281). See the sqlite migration of the same number
-- for what the column holds, why it and ip_address are the "same device" key from here, and why
-- pre-upgrade rows reading '' is accepted rather than backfilled.
--
-- The width matches codes.user_agent.
ALTER TABLE user_sessions ADD COLUMN user_agent varchar(512) NOT NULL DEFAULT '';
