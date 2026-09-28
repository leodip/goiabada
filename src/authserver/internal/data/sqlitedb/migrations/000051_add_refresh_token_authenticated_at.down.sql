-- The instant is gone with the column, so an ROPC refresh after this down migration writes the
-- moment of the refresh as auth_time again, which is what every ROPC refresh did before 000051.
-- Nothing indexes or constrains the column, which is SQLite's requirement before DROP COLUMN.
ALTER TABLE refresh_tokens DROP COLUMN authenticated_at;
