-- Reverses migration 000093 (#815): drops every brand's custom palette.
ALTER TABLE brands DROP COLUMN palette;
