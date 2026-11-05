-- The "Let users delete their own account" setting (#783 decision 5): whether a user may delete
-- their own account from their account pages in the admin console. Administrators delete any user
-- whatever it says.
--
-- The default is on, the value a new deployment is seeded with, so an upgraded deployment gets it
-- too (#744), and a rolling upgrade rests on it: the previous release, still serving while this one
-- migrates, saves settings naming no account_deletion_enabled, which leaves it as stored.
--
-- BOOLEAN, as pkce_required, the row's other boolean added with a default.
ALTER TABLE settings ADD COLUMN account_deletion_enabled BOOLEAN NOT NULL DEFAULT 1;
