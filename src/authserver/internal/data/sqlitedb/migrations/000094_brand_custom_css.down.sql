-- Reverses migration 000094 (#816): drops every brand's custom CSS.
ALTER TABLE brands DROP COLUMN custom_css;
