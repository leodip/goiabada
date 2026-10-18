-- The UI theme is one of three values now: empty (automatic), "light" or "dark" (#617). See the
-- sqlite migration of the same number for why each stored theme maps as it does.
--
-- The column's collation, utf8mb4_0900_as_cs, compares case and trailing spaces exactly but is
-- linguistic, so 'da' U+00AD 'rk' (a soft hyphen, which it ignores) = 'dark' holds. Comparing the
-- bytes makes the comparison exact, as on SQLite and PostgreSQL, so a value no list offered becomes
-- light whatever it looks like. A binary string is never padded, so trailing spaces still count.
UPDATE `settings` SET `ui_theme` = CASE
  WHEN CAST(`ui_theme` AS BINARY) IN ('', 'dark', 'synthwave', 'halloween', 'forest', 'aqua', 'black',
    'luxury', 'dracula', 'business', 'night', 'coffee', 'dim', 'sunset') THEN 'dark'
  ELSE 'light'
END;
