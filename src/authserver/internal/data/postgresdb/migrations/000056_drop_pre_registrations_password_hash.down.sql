-- Migration 000056 down: re-add pre_registrations.password_hash with the type and nullability
-- 000055 left it in. The shape comes back, never the values: the column is added with an
-- empty-string default so the rows it finds can satisfy NOT NULL, and the default is then
-- dropped, because 000055's column had none.
ALTER TABLE pre_registrations ADD COLUMN password_hash character varying(64) NOT NULL DEFAULT '';
ALTER TABLE pre_registrations ALTER COLUMN password_hash DROP DEFAULT;
