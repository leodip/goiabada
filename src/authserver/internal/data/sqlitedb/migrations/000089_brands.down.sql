-- Reverses migration 000089 (#810): the default brand's appearance goes back into ui_theme, the
-- automatic one as the empty value ui_theme stores it as, then the pointer and every brand are
-- dropped. A theme saved through the previous release after 000089 is overwritten by the brand's.
UPDATE settings SET ui_theme = (
    SELECT CASE brands.appearance WHEN 'light' THEN 'light' WHEN 'dark' THEN 'dark' ELSE '' END
    FROM brands WHERE brands.id = settings.default_brand_id
) WHERE default_brand_id IS NOT NULL;

DROP INDEX idx_settings_default_brand_id;
ALTER TABLE settings DROP COLUMN default_brand_id;
DROP TABLE brands;
