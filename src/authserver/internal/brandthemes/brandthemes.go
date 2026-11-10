package brandthemes

import (
	"crypto/sha256"
	"encoding/hex"
	"maps"
	"strconv"
	"strings"

	"github.com/leodip/goiabada/core/errs"
)

// Palette is one mode of a theme: a #rrggbb value for each of the 23 color tokens ui.css declares,
// by the token's name without its --color- prefix.
type Palette map[string]string

// Preset is a built-in theme: the key a brand stores and the admin API carries, and its light and
// dark palettes.
type Preset struct {
	Key   string
	Light Palette
	Dark  Palette
}

// blueberry is the key of the theme ui.css holds, whose stylesheet declares no colors.
const blueberry = "blueberry"

// tokens are the 23 color tokens in the order ui.css declares them, which is the order a stylesheet
// sets them in.
var tokens = []string{
	"canvas", "surface", "subtle", "line", "line-strong", "ink", "ink-muted",
	"brand", "brand-strong", "on-brand", "brand-soft",
	"danger", "danger-strong", "on-danger", "danger-soft", "danger-ink",
	"positive-soft", "positive-ink", "caution-soft", "caution-ink", "note-soft", "note-ink",
	"focus",
}

// All returns the built-in themes in display order, the order the brand editor and the admin API
// list them in. The palettes are copies, so a caller cannot change a theme.
func All() []Preset {
	all := make([]Preset, len(presets))
	for i, preset := range presets {
		all[i] = Preset{Key: preset.Key, Light: maps.Clone(preset.Light), Dark: maps.Clone(preset.Dark)}
	}
	return all
}

// Get returns the built-in theme of key, a copy as All's are, and whether there is one.
func Get(key string) (Preset, bool) {
	for _, preset := range presets {
		if preset.Key == key {
			return Preset{Key: preset.Key, Light: maps.Clone(preset.Light), Dark: maps.Clone(preset.Dark)}, true
		}
	}
	return Preset{}, false
}

// StylesheetRoute is the route a brand's stylesheet is served at, the brand's id in {id}.
const StylesheetRoute = "/brand/{id}/stylesheet.css"

// Stylesheet is the stylesheet a brand on a theme is drawn with, and the fingerprint of its
// contents a page links it by.
type Stylesheet struct {
	CSS         string
	Fingerprint string
}

// stylesheets are every theme's stylesheet, built once: they change only with a release.
var stylesheets = buildStylesheets()

// StylesheetOf returns the stylesheet of the built-in theme of key, and whether there is one.
func StylesheetOf(key string) (Stylesheet, bool) {
	stylesheet, ok := stylesheets[key]
	return stylesheet, ok
}

// StylesheetPath returns the path a page links a brand's stylesheet by: the brand's id, and the
// fingerprint of the stylesheet its theme draws, so the path changes exactly when the stylesheet
// does and a browser may keep it for a year. A theme that is none of the built-in ones is an error.
func StylesheetPath(brandId int64, theme string) (string, error) {
	stylesheet, ok := stylesheets[theme]
	if !ok {
		return "", errs.Errorf("brand %d has the theme %q, which is none of the built-in themes", brandId, theme)
	}
	path := strings.Replace(StylesheetRoute, "{id}", strconv.FormatInt(brandId, 10), 1)
	return path + "?v=" + stylesheet.Fingerprint, nil
}

func buildStylesheets() map[string]Stylesheet {
	built := make(map[string]Stylesheet, len(presets))
	for _, preset := range presets {
		css := stylesheetCSS(preset)
		digest := sha256.Sum256([]byte(css))
		built[preset.Key] = Stylesheet{CSS: css, Fingerprint: hex.EncodeToString(digest[:6])}
	}
	return built
}

// stylesheetCSS sets every color token to the theme's light value on the root, and to its dark
// value under the two conditions ui.css's dark variant applies the dark palette on: data-theme is
// dark, or the device prefers dark and data-theme is not light. The stylesheet is linked after
// main.css and is not in a layer, so it wins over main.css's tokens, and each dark rule is more
// specific than the light one, so it wins over that.
//
// Blueberry declares no colors: main.css already holds them, and an operator who regenerated it with
// their own keeps those on Blueberry (#810 decision 4).
func stylesheetCSS(preset Preset) string {
	if preset.Key == blueberry {
		return "/* Blueberry is the palette main.css is built with: this stylesheet declares no colors. */\n"
	}
	declarations := func(palette Palette, indent string) string {
		var b strings.Builder
		for _, token := range tokens {
			b.WriteString(indent + "--color-" + token + ": " + palette[token] + ";\n")
		}
		return b.String()
	}
	return ":root {\n" + declarations(preset.Light, "  ") + "}\n" +
		"\n" +
		"@media (prefers-color-scheme: dark) {\n" +
		"  :root:not([data-theme=\"light\"]) {\n" + declarations(preset.Dark, "    ") + "  }\n" +
		"}\n" +
		"\n" +
		":root[data-theme=\"dark\"] {\n" + declarations(preset.Dark, "  ") + "}\n"
}
