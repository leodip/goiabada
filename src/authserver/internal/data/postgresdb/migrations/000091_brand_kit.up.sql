-- The brand kit (#813 decision 2). See the sqlite migration of the same number for why and for the
-- six questions. PostgreSQL compares strings byte-wise, so no column needs a collation pin.
-- Timestamps are written in UTC, as Go writes them.
CREATE TABLE brand_assets (
    id BIGSERIAL PRIMARY KEY,
    created_at TIMESTAMP(6) NOT NULL,
    kind VARCHAR(16) NOT NULL,
    content_type VARCHAR(64) NOT NULL,
    fingerprint VARCHAR(64) NOT NULL,
    width INTEGER NOT NULL,
    height INTEGER NOT NULL,
    content BYTEA NOT NULL
);
CREATE INDEX idx_brand_assets_created_at ON brand_assets (created_at);

ALTER TABLE brands ADD COLUMN corners VARCHAR(16) NOT NULL DEFAULT 'rounded';
ALTER TABLE brands ADD COLUMN font VARCHAR(16) NOT NULL DEFAULT 'system-ui';
ALTER TABLE brands ADD COLUMN background_fit VARCHAR(16) NOT NULL DEFAULT 'cover';
ALTER TABLE brands ADD COLUMN hide_app_name BOOLEAN NOT NULL DEFAULT false;

ALTER TABLE brands ADD COLUMN logo_asset_id BIGINT NULL;
ALTER TABLE brands ADD COLUMN dark_logo_asset_id BIGINT NULL;
ALTER TABLE brands ADD COLUMN favicon_asset_id BIGINT NULL;
ALTER TABLE brands ADD COLUMN background_asset_id BIGINT NULL;
ALTER TABLE brands ADD COLUMN regular_font_asset_id BIGINT NULL;
ALTER TABLE brands ADD COLUMN bold_font_asset_id BIGINT NULL;

ALTER TABLE brands ADD CONSTRAINT fk_brands_logo_asset
    FOREIGN KEY (logo_asset_id) REFERENCES brand_assets (id);
ALTER TABLE brands ADD CONSTRAINT fk_brands_dark_logo_asset
    FOREIGN KEY (dark_logo_asset_id) REFERENCES brand_assets (id);
ALTER TABLE brands ADD CONSTRAINT fk_brands_favicon_asset
    FOREIGN KEY (favicon_asset_id) REFERENCES brand_assets (id);
ALTER TABLE brands ADD CONSTRAINT fk_brands_background_asset
    FOREIGN KEY (background_asset_id) REFERENCES brand_assets (id);
ALTER TABLE brands ADD CONSTRAINT fk_brands_regular_font_asset
    FOREIGN KEY (regular_font_asset_id) REFERENCES brand_assets (id);
ALTER TABLE brands ADD CONSTRAINT fk_brands_bold_font_asset
    FOREIGN KEY (bold_font_asset_id) REFERENCES brand_assets (id);

CREATE INDEX idx_brands_logo_asset_id ON brands (logo_asset_id);
CREATE INDEX idx_brands_dark_logo_asset_id ON brands (dark_logo_asset_id);
CREATE INDEX idx_brands_favicon_asset_id ON brands (favicon_asset_id);
CREATE INDEX idx_brands_background_asset_id ON brands (background_asset_id);
CREATE INDEX idx_brands_regular_font_asset_id ON brands (regular_font_asset_id);
CREATE INDEX idx_brands_bold_font_asset_id ON brands (bold_font_asset_id);
