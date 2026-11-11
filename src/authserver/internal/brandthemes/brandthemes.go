package brandthemes

import (
	"crypto/sha256"
	"encoding/hex"
	"maps"
	"strconv"
	"strings"

	"github.com/leodip/goiabada/authserver/internal/record"
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

// StylesheetRoute is the route a brand's full stylesheet is served at, the brand's id in {id}.
const StylesheetRoute = "/brand/{id}/stylesheet.css"

// Stylesheet is a stylesheet a brand is drawn with, and the fingerprint of its contents a page
// links it by.
type Stylesheet struct {
	CSS         string
	Fingerprint string
}

// stylesheets are every theme's colors stylesheet, built once: they change only with a release.
var stylesheets = buildStylesheets()

// StylesheetOf returns the colors stylesheet of the built-in theme of key, and whether there is one.
func StylesheetOf(key string) (Stylesheet, bool) {
	stylesheet, ok := stylesheets[key]
	return stylesheet, ok
}

// ColorsStylesheetRoute is the route a brand's colors-only stylesheet is served at, the brand's id
// in {id}: the stylesheet the admin console's admin pages link, so they take a brand's colors and
// never its kit (#813 decision 9).
const ColorsStylesheetRoute = "/brand/{id}/colors.css"

// cornerRadii are the two radius tokens ui.css declares, --radius-control and --radius-panel, for
// each corner shape but rounded, whose are today's, main.css's (#813). Square rounds nothing. Pill
// rounds a single-line control fully, and the card and the other panels to 1.5rem, which leaves
// their content unclipped; ui.css holds a multi-line box drawn with --radius-control (a text area,
// a notice, a list) to 1rem, so it is rounded only as far as its content stays unclipped too.
var cornerRadii = map[record.BrandCorners][2]string{
	record.BrandCornersSquare: {"0", "0"},
	record.BrandCornersPill:   {"9999px", "1.5rem"},
}

// fontStacks are the five system families besides System UI, each a list of fonts a visitor's
// device already has, so neither the server nor a visitor downloads a font for them (#813 decision
// 7). They are the matching text stacks of Modern Font Stacks (modernfontstacks.com, public domain):
// Humanist, Geometric Humanist, Transitional, Neo-Grotesque and Rounded Sans. System UI is today's
// family, main.css's --font-sans, so it declares none; the uploaded font draws a file its slot names.
var fontStacks = map[record.BrandFont]string{
	record.BrandFontHumanist:     "Seravek, 'Gill Sans Nova', Ubuntu, Calibri, 'DejaVu Sans', source-sans-pro, sans-serif",
	record.BrandFontGeometric:    "Avenir, Montserrat, Corbel, 'URW Gothic', source-sans-pro, sans-serif",
	record.BrandFontSerif:        "Charter, 'Bitstream Charter', 'Sitka Text', Cambria, serif",
	record.BrandFontNeoGrotesque: "Inter, Roboto, 'Helvetica Neue', 'Arial Nova', 'Nimbus Sans', Arial, sans-serif",
	record.BrandFontRounded:      "ui-rounded, 'Hiragino Maru Gothic ProN', Quicksand, Comfortaa, Manjari, 'Arial Rounded MT', 'Arial Rounded MT Bold', Calibri, source-sans-pro, sans-serif",
}

// FullStylesheet returns the stylesheet brand is drawn with on the auth server's pages and the
// console's end-user pages: its theme's colors, as ColorsStylesheet answers them, then one rule on
// the root setting the tokens its kit changes, its corners' two radii and its family's
// --font-sans, which every text but monospace is drawn in (#813 decision 9). A choice drawn as today
// sets no token, so a brand nobody has changed is drawn exactly as before the kit, and its full
// stylesheet is its colors-only one. A theme that is none of the built-in ones is an error.
func FullStylesheet(brand *record.Brand) (Stylesheet, error) {
	colors, err := ColorsStylesheet(brand)
	if err != nil {
		return Stylesheet{}, err
	}
	var kit strings.Builder
	if radii, ok := cornerRadii[brand.Corners]; ok {
		kit.WriteString("  --radius-control: " + radii[0] + ";\n")
		kit.WriteString("  --radius-panel: " + radii[1] + ";\n")
	}
	if stack, ok := fontStacks[brand.Font]; ok {
		kit.WriteString("  --font-sans: " + stack + ";\n")
	}
	if kit.Len() == 0 {
		return colors, nil
	}
	return newStylesheet(colors.CSS + "\n:root {\n" + kit.String() + "}\n"), nil
}

// ColorsStylesheet returns the stylesheet that sets brand's colors alone, its theme's, whatever its
// kit holds. A theme that is none of the built-in ones is an error.
func ColorsStylesheet(brand *record.Brand) (Stylesheet, error) {
	stylesheet, ok := stylesheets[brand.Theme]
	if !ok {
		return Stylesheet{}, errs.Errorf("brand %d has the theme %q, which is none of the built-in themes", brand.Id, brand.Theme)
	}
	return stylesheet, nil
}

// StylesheetPath returns the path a page links brand's full stylesheet by: the brand's id, and the
// fingerprint of the stylesheet's contents, so the path changes exactly when the stylesheet does and
// a browser may keep it for a year. A theme that is none of the built-in ones is an error.
func StylesheetPath(brand *record.Brand) (string, error) {
	stylesheet, err := FullStylesheet(brand)
	if err != nil {
		return "", err
	}
	return linkPath(StylesheetRoute, brand.Id, stylesheet), nil
}

// ColorsStylesheetPath returns the path a page links brand's colors-only stylesheet by, as
// StylesheetPath does the full one's.
func ColorsStylesheetPath(brand *record.Brand) (string, error) {
	stylesheet, err := ColorsStylesheet(brand)
	if err != nil {
		return "", err
	}
	return linkPath(ColorsStylesheetRoute, brand.Id, stylesheet), nil
}

func linkPath(route string, brandId int64, stylesheet Stylesheet) string {
	path := strings.Replace(route, "{id}", strconv.FormatInt(brandId, 10), 1)
	return path + "?v=" + stylesheet.Fingerprint
}

// newStylesheet is css with its fingerprint: the first twelve hex digits of its SHA-256, as a static
// file's.
func newStylesheet(css string) Stylesheet {
	digest := sha256.Sum256([]byte(css))
	return Stylesheet{CSS: css, Fingerprint: hex.EncodeToString(digest[:6])}
}

func buildStylesheets() map[string]Stylesheet {
	built := make(map[string]Stylesheet, len(presets))
	for _, preset := range presets {
		built[preset.Key] = newStylesheet(stylesheetCSS(preset))
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
