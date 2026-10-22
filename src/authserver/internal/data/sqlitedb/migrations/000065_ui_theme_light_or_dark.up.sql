-- The UI theme is one of three values now: empty, which follows each visitor's device between light
-- and dark, "light" or "dark" (#617). daisyUI and its 32 themes are gone, so a stored theme becomes
-- the one of the two that looks like it: the 13 themes daisyUI drew dark become "dark", the other 19
-- "light".
--
-- The empty value becomes "dark", because until this release it drew the pages dark, and a
-- deployment that never chose a theme keeps the look it had. Empty means automatic from here on,
-- which new installations start with. Any other value, which daisyUI drew in its default light
-- theme, becomes "light".
--
-- The down migration changes nothing: "light" and "dark" were themes before this release too.
UPDATE settings SET ui_theme = CASE
  WHEN ui_theme IN ('', 'dark', 'synthwave', 'halloween', 'forest', 'aqua', 'black', 'luxury', 'dracula',
    'business', 'night', 'coffee', 'dim', 'sunset') THEN 'dark'
  ELSE 'light'
END;
