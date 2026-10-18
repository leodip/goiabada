-- The UI theme is one of three values now: empty (automatic), "light" or "dark" (#617). See the
-- sqlite migration of the same number for why each stored theme maps as it does.
--
-- The comparison is exact, as on SQLite and PostgreSQL: a binary collation, so case and ignorable
-- characters count, and a '|' after each side, since SQL Server pads the shorter string with spaces
-- before comparing, so 'dark ' = 'dark' would otherwise hold.
UPDATE [settings] SET [ui_theme] = CASE
  WHEN [ui_theme] COLLATE Latin1_General_100_BIN2 + N'|' IN (N'|', N'dark|', N'synthwave|', N'halloween|',
    N'forest|', N'aqua|', N'black|', N'luxury|', N'dracula|', N'business|', N'night|', N'coffee|', N'dim|',
    N'sunset|') THEN N'dark'
  ELSE N'light'
END;
