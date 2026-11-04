-- The "Keep users signed in after the browser closes" setting (#743 decisions 3 and 4): whether the
-- auth server's signed-in cookie outlives the browser. One of 'always', 'ask' (each user chooses on
-- the password page) and 'never', lower-case as the admin API's keepSignedIn spells it.
--
-- The default is 'ask', the value a new deployment is seeded with, so an upgraded deployment gets it
-- too, and a rolling upgrade rests on it: the previous release, still serving while this one
-- migrates, saves settings naming no keep_signed_in, which leaves it as stored.
ALTER TABLE settings ADD COLUMN keep_signed_in TEXT NOT NULL DEFAULT 'ask';
