-- Reverses migration 000089 (#810). See the sqlite migration for what is lost.
UPDATE settings SET ui_theme = (
    SELECT CASE brands.appearance WHEN 'light' THEN 'light' WHEN 'dark' THEN 'dark' ELSE '' END
    FROM brands WHERE brands.id = settings.default_brand_id
) WHERE default_brand_id IS NOT NULL;

DROP INDEX idx_settings_default_brand_id;
ALTER TABLE settings DROP CONSTRAINT fk_settings_default_brand;
ALTER TABLE settings DROP COLUMN default_brand_id;
DROP TABLE brands;
