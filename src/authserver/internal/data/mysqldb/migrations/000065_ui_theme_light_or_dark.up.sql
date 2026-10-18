-- The UI theme is one of three values now: empty (automatic), "light" or "dark" (#617). See the
-- sqlite migration of the same number for why each stored theme maps as it does.
UPDATE `settings` SET `ui_theme` = CASE
  WHEN `ui_theme` IN ('', 'dark', 'synthwave', 'halloween', 'forest', 'aqua', 'black', 'luxury', 'dracula',
    'business', 'night', 'coffee', 'dim', 'sunset') THEN 'dark'
  ELSE 'light'
END;
