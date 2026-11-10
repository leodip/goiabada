-- Brands (#810 decisions 1, 2 and 5): a brand is a name, an appearance and a theme, and the
-- settings row points at the default one, in whose appearance and theme every page is drawn.
--
-- The six questions a migration answers: (1) all four engines. (2) name is pinned case-sensitive
-- on MySQL and SQL Server, as every string column is; appearance and theme hold the API's lower-case
-- keys. (3) Names are compared by the unique index, as every name in the schema is. (4) name is
-- unique among brands, the engine's to refuse, so two creates racing for a name cannot both win. (5) An installation that had a theme gets one brand, named Default, on the
-- Blueberry theme, its colors until now, whose appearance is the stored light or dark, compared
-- exactly, and automatic for anything else, the empty value included; the settings row points at
-- it. A new installation has no settings row when this runs, and its first start seeds the brand.
-- (6) Each schema.golden gains the table, the column and its index.
--
-- settings.default_brand_id is a foreign key to the brand, with no cascade, so the engine refuses
-- deleting the brand it points at. It is nullable because SQLite cannot add a foreign-key column
-- with a non-NULL default, and the four engines agree: this migration and the first start's seed
-- fill it, and nothing clears it.
--
-- ui_theme is left as it is, and nothing from this release reads it. The previous release names it
-- in every read of the settings row, so a replica of it still serving during a rolling upgrade
-- keeps working and keeps the theme it drew (decision 2). The down migration writes the default
-- brand's appearance back into it.
CREATE TABLE brands (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at DATETIME,
    updated_at DATETIME,
    name TEXT NOT NULL,
    appearance TEXT NOT NULL,
    theme TEXT NOT NULL
);
CREATE UNIQUE INDEX idx_brands_name ON brands (name);

ALTER TABLE settings ADD COLUMN default_brand_id INTEGER NULL
    CONSTRAINT fk_settings_default_brand REFERENCES brands (id);
CREATE INDEX idx_settings_default_brand_id ON settings (default_brand_id);

INSERT INTO brands (created_at, updated_at, name, appearance, theme)
SELECT datetime('now'), datetime('now'), 'Default',
    CASE ui_theme WHEN 'light' THEN 'light' WHEN 'dark' THEN 'dark' ELSE 'auto' END,
    'blueberry'
FROM settings WHERE id = 1;

UPDATE settings SET default_brand_id = (SELECT id FROM brands WHERE name = 'Default') WHERE id = 1;
