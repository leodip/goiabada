-- Brands (#810 decisions 1, 2 and 5). See the sqlite migration of the same number for why and for
-- the six questions. PostgreSQL compares strings byte-wise, so no column needs a collation pin and
-- the stored theme is compared exactly as it is. Timestamps are written in UTC, as Go writes them.
CREATE TABLE brands (
    id BIGSERIAL PRIMARY KEY,
    created_at TIMESTAMP(6),
    updated_at TIMESTAMP(6),
    name VARCHAR(60) NOT NULL,
    appearance VARCHAR(10) NOT NULL,
    theme VARCHAR(32) NOT NULL
);
CREATE UNIQUE INDEX idx_brands_name ON brands (name);

ALTER TABLE settings ADD COLUMN default_brand_id BIGINT NULL;
ALTER TABLE settings ADD CONSTRAINT fk_settings_default_brand
    FOREIGN KEY (default_brand_id) REFERENCES brands (id);
CREATE INDEX idx_settings_default_brand_id ON settings (default_brand_id);

INSERT INTO brands (created_at, updated_at, name, appearance, theme)
SELECT NOW() AT TIME ZONE 'UTC', NOW() AT TIME ZONE 'UTC', 'Default',
    CASE ui_theme WHEN 'light' THEN 'light' WHEN 'dark' THEN 'dark' ELSE 'auto' END,
    'blueberry'
FROM settings WHERE id = 1;

UPDATE settings SET default_brand_id = (SELECT id FROM brands WHERE name = 'Default') WHERE id = 1;
