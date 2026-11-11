-- The brand kit (#813 decision 2): brand_assets holds each uploaded file of a brand's kit, and
-- brands gains its four choices and six slots, each slot naming an asset.
--
-- The six questions a migration answers: (1) all four engines. (2) kind, content_type,
-- fingerprint and the three choices hold ASCII keys and validated values; they are pinned
-- case-sensitive on MySQL and SQL Server, as every string column is. (3) Nothing is compared by
-- the engine but ids and created_at. (4) Each slot is a foreign key to brand_assets(id) with no
-- cascade: the engine refuses a slot naming no asset, and refuses deleting an asset a slot names,
-- so the sweep, which deletes only assets no slot names, is the one thing that deletes assets.
-- (5) Every existing brand is drawn as before: rounded, on the System UI family, its background
-- fitted as cover, the app name shown, through the columns' defaults, and every slot empty. (6)
-- Each schema.golden gains the table, its index, the ten columns, the six foreign keys and their
-- indexes.
--
-- An asset row never changes after the upload, so it has no updated_at. created_at is required
-- and indexed, since the sweep deletes by age. width and height are the image's pixel size, zero
-- for a font. Nothing on the asset names a brand: a replaced or removed asset, and the assets of a
-- deleted brand, are simply named by no slot any more.
--
-- The previous release never reads brands, so a replica of it still serving during a rolling
-- upgrade keeps working. The down migration drops the kit, and every asset and choice with it.
CREATE TABLE brand_assets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at DATETIME NOT NULL,
    kind TEXT NOT NULL,
    content_type TEXT NOT NULL,
    fingerprint TEXT NOT NULL,
    width INTEGER NOT NULL,
    height INTEGER NOT NULL,
    content BLOB NOT NULL
);
CREATE INDEX idx_brand_assets_created_at ON brand_assets (created_at);

ALTER TABLE brands ADD COLUMN corners TEXT NOT NULL DEFAULT 'rounded';
ALTER TABLE brands ADD COLUMN font TEXT NOT NULL DEFAULT 'system-ui';
ALTER TABLE brands ADD COLUMN background_fit TEXT NOT NULL DEFAULT 'cover';
ALTER TABLE brands ADD COLUMN hide_app_name numeric NOT NULL DEFAULT 0;

ALTER TABLE brands ADD COLUMN logo_asset_id INTEGER NULL
    CONSTRAINT fk_brands_logo_asset REFERENCES brand_assets (id);
ALTER TABLE brands ADD COLUMN dark_logo_asset_id INTEGER NULL
    CONSTRAINT fk_brands_dark_logo_asset REFERENCES brand_assets (id);
ALTER TABLE brands ADD COLUMN favicon_asset_id INTEGER NULL
    CONSTRAINT fk_brands_favicon_asset REFERENCES brand_assets (id);
ALTER TABLE brands ADD COLUMN background_asset_id INTEGER NULL
    CONSTRAINT fk_brands_background_asset REFERENCES brand_assets (id);
ALTER TABLE brands ADD COLUMN regular_font_asset_id INTEGER NULL
    CONSTRAINT fk_brands_regular_font_asset REFERENCES brand_assets (id);
ALTER TABLE brands ADD COLUMN bold_font_asset_id INTEGER NULL
    CONSTRAINT fk_brands_bold_font_asset REFERENCES brand_assets (id);

CREATE INDEX idx_brands_logo_asset_id ON brands (logo_asset_id);
CREATE INDEX idx_brands_dark_logo_asset_id ON brands (dark_logo_asset_id);
CREATE INDEX idx_brands_favicon_asset_id ON brands (favicon_asset_id);
CREATE INDEX idx_brands_background_asset_id ON brands (background_asset_id);
CREATE INDEX idx_brands_regular_font_asset_id ON brands (regular_font_asset_id);
CREATE INDEX idx_brands_bold_font_asset_id ON brands (bold_font_asset_id);
