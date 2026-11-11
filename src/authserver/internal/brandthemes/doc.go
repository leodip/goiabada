// Package brandthemes holds the eight built-in themes a brand is drawn in, each a light and a dark
// palette of the 23 color tokens ui.css declares, and a brand's two stylesheets (#810, #813): the
// colors-only one, its theme's colors, and the full one, those colors and the tokens its corners
// and system font family set. Blueberry is the palette ui.css holds; the others are named after fruits, as
// Goiabada is after the guava, and High contrast keeps the name people look for it by. Every
// palette is held to WCAG 2.2 AA contrast, and High contrast's text to 7:1, by the auth server's
// web tests.
package brandthemes
