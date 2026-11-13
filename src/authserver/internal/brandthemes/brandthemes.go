package brandthemes

import (
	"crypto/sha256"
	"encoding/hex"
	"maps"
	"strconv"
	"strings"

	"github.com/leodip/goiabada/authserver/internal/brandasset"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/brandkit"
	"github.com/leodip/goiabada/core/errs"
	"github.com/leodip/goiabada/core/palette"
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

// SafeStylesheetRoute and SafeColorsStylesheetRoute are the routes a brand's two safe stylesheets
// are served at, the brand's id in {id}: what SafeFullStylesheet and SafeColorsStylesheet answer,
// which a page drawn in safe mode links in place of the brand's own two (#816 decision 3).
const (
	SafeStylesheetRoute       = "/brand/{id}/safe-stylesheet.css"
	SafeColorsStylesheetRoute = "/brand/{id}/safe-colors.css"
)

// FullStylesheet returns the stylesheet brand is drawn with on the auth server's pages and the
// console's end-user pages: its theme's colors, as ColorsStylesheet answers them, then its kit
// (#813 decision 9). slots are the assets brand's slots name, read without their bytes.
//
//   - The uploaded font, while the font is uploaded and a regular font file fills its slot: one
//     @font-face per file, swapped in once loaded. With one file it declares no weight, so the file
//     is used for every weight; with a bold file too, the regular one draws the weights up to 500 and
//     the bold one the heavier ones (decision 7). Files left attached beside a system family load
//     nothing.
//   - One rule on the root setting the tokens the kit changes: its corners' two radii and its
//     family's --font-sans, which every text but monospace is drawn in, the uploaded font followed
//     by the System UI family.
//   - The background image, on the card pages' .auth-page, over the theme's background color, so a
//     contained image leaves that color around it and one that fails to load leaves the page as it
//     was (decision 6): cover and contain centred on the window, tile repeated at its own size.
//   - The brand's custom CSS, last and as it was stored (#816), which the admin API checked can make
//     a browser request nothing. The colors-only stylesheet never carries it, so it reaches the
//     pages linking the full stylesheet and never the console's admin pages.
//
// A choice drawn as today sets nothing, so a brand nobody has changed and with no custom CSS is
// drawn exactly as before the kit, and its full stylesheet is its colors-only one. The logo, the
// dark logo and the favicon are the page's to draw. A theme that is none of the built-in ones is an
// error, as ColorsStylesheet says.
func FullStylesheet(brand *record.Brand, slots brandasset.Slots) (Stylesheet, error) {
	colors, err := ColorsStylesheet(brand)
	if err != nil {
		return Stylesheet{}, err
	}
	var rules []string

	uploadedFont := brand.Font == record.BrandFontUploaded && slots.RegularFont != nil
	if uploadedFont {
		if slots.BoldFont == nil {
			rules = append(rules, fontFace(slots.RegularFont, ""))
		} else {
			rules = append(rules, fontFace(slots.RegularFont, brandkit.RegularFontWeights), fontFace(slots.BoldFont, brandkit.BoldFontWeights))
		}
	}

	// The corners' radii and the family's list are brandkit's, which the console's editor draws its
	// sample from too. The uploaded font's list is set only while a regular font file is there to
	// draw it; without one the brand is drawn in System UI, which sets nothing.
	var root strings.Builder
	if radii, ok := brandkit.CornerRadii(string(brand.Corners)); ok {
		root.WriteString("  --radius-control: " + radii.Control + ";\n")
		root.WriteString("  --radius-panel: " + radii.Panel + ";\n")
	}
	if brand.Font != record.BrandFontUploaded || uploadedFont {
		if stack, ok := brandkit.FontStack(string(brand.Font)); ok {
			root.WriteString("  --font-sans: " + stack + ";\n")
		}
	}
	if root.Len() > 0 {
		rules = append(rules, ":root {\n"+root.String()+"}\n")
	}

	if slots.Background != nil {
		rules = append(rules, backgroundRule(slots.Background, brand.BackgroundFit))
	}

	// The custom CSS goes last, as it was stored, so its rules win over everything before them
	// that they match as specifically, and nothing after it can be swallowed by a block it leaves
	// open (#816).
	if brand.CustomCSS != "" {
		rules = append(rules, brand.CustomCSS)
	}

	if len(rules) == 0 {
		return colors, nil
	}
	return newStylesheet(colors.CSS + "\n" + strings.Join(rules, "\n")), nil
}

// SafeFullStylesheet returns the stylesheet brand is drawn with in safe mode: FullStylesheet's, without
// what an administrator authors freely (#816 decision 1). The custom CSS is left out, Blueberry's
// colors take a custom palette's place, and the System UI family an uploaded font's, so no font file
// is loaded. Everything else is drawn as FullStylesheet draws it: a built-in theme's colors, the
// corners, a system family and the background. Nothing stored is read differently or changed.
//
// It never reads a custom brand's palette, so it draws a brand whose palette cannot be drawn too.
func SafeFullStylesheet(brand *record.Brand, slots brandasset.Slots) (Stylesheet, error) {
	if brand.Font == record.BrandFontUploaded {
		// With no font file in its slot, an uploaded font is drawn in System UI and sets nothing.
		slots.RegularFont, slots.BoldFont = nil, nil
	}
	return FullStylesheet(safeBrand(brand), slots)
}

// SafeColorsStylesheet returns the colors-only stylesheet brand is drawn with in safe mode:
// ColorsStylesheet's, with Blueberry's colors in place of a custom palette (#816 decision 1).
func SafeColorsStylesheet(brand *record.Brand) (Stylesheet, error) {
	return ColorsStylesheet(safeBrand(brand))
}

// safeBrand is a copy of brand with what safe mode sets aside of the brand itself set aside: no custom
// CSS, and Blueberry in place of the custom theme. The uploaded font is in the slots, which
// SafeFullStylesheet empties.
func safeBrand(brand *record.Brand) *record.Brand {
	safe := *brand
	safe.CustomCSS = ""
	if safe.Theme == record.BrandThemeCustom {
		safe.Theme, safe.Palette = blueberry, nil
	}
	return &safe
}

// fontFace is the @font-face rule of an uploaded font file, for the weights in weight, or for every
// weight when weight is empty.
func fontFace(font *record.BrandAsset, weight string) string {
	var b strings.Builder
	b.WriteString("@font-face {\n")
	b.WriteString("  font-family: " + brandkit.UploadedFontFamily + ";\n")
	b.WriteString("  src: url(\"" + brandasset.Path(font) + "\") format(\"woff2\");\n")
	if weight != "" {
		b.WriteString("  font-weight: " + weight + ";\n")
	}
	b.WriteString("  font-display: swap;\n")
	b.WriteString("}\n")
	return b.String()
}

// backgroundRule draws background behind the card at fit, laid out as brandkit lays it out, which
// the console's sample of a sign-in page draws it from too. A fit that is none of the three, which no
// write stores, draws as cover, the fit migration 000091 gives every brand. A cover or contained image
// is fixed to the window, so it stays put behind a card taller than the screen.
func backgroundRule(background *record.BrandAsset, fit record.BrandBackgroundFit) string {
	layout := brandkit.BackgroundLayout(string(fit))
	var b strings.Builder
	b.WriteString(".auth-page {\n")
	b.WriteString("  background-image: url(\"" + brandasset.Path(background) + "\");\n")
	if layout.Position != "" {
		b.WriteString("  background-position: " + layout.Position + ";\n")
	}
	if layout.Size != "" {
		b.WriteString("  background-size: " + layout.Size + ";\n")
	}
	b.WriteString("  background-repeat: " + layout.Repeat + ";\n")
	if layout.Size != "" {
		b.WriteString("  background-attachment: fixed;\n")
	}
	b.WriteString("}\n")
	return b.String()
}

// ColorsStylesheet returns the stylesheet that sets brand's colors alone, its theme's, whatever its
// kit holds: a built-in theme's, or a custom brand's stored palette (#815). A theme that is none of
// the built-in ones is an error, and so is a custom brand whose palette cannot be drawn.
func ColorsStylesheet(brand *record.Brand) (Stylesheet, error) {
	if brand.Theme == record.BrandThemeCustom {
		return customStylesheet(brand)
	}
	stylesheet, ok := stylesheets[brand.Theme]
	if !ok {
		return Stylesheet{}, errs.Errorf("brand %d has the theme %q, which is none of the built-in themes", brand.Id, brand.Theme)
	}
	return stylesheet, nil
}

// customStylesheet is the colors stylesheet of a brand on the custom theme: its stored palette's 23
// colors of each mode, set as a built-in theme's are, whichever mode made the palette (#815 decision
// 1). It is built on each call, from what the brand stores, and does no color math. A custom brand
// with no palette, or with a mode missing a token or holding a value that is not a #rrggbb color,
// cannot be drawn, which only a hand edit of the database makes: it is an error, as an unknown theme
// is, so a value never reaches the stylesheet unless it is a color (decision 3).
func customStylesheet(brand *record.Brand) (Stylesheet, error) {
	if brand.Palette == nil {
		return Stylesheet{}, errs.Errorf("brand %d has the custom theme and no palette", brand.Id)
	}
	for _, mode := range []struct {
		name   string
		colors map[string]string
	}{{"light", brand.Palette.Light}, {"dark", brand.Palette.Dark}} {
		for _, token := range tokens {
			if !palette.IsColor(mode.colors[token]) {
				return Stylesheet{}, errs.Errorf("brand %d has a custom palette whose %s %s color is not a #rrggbb color",
					brand.Id, mode.name, token)
			}
		}
	}
	return newStylesheet(colorsCSS(brand.Palette.Light, brand.Palette.Dark)), nil
}

// StylesheetPath returns the path a page links brand's full stylesheet by, slots being the assets its
// slots name: the brand's id, and the fingerprint of the stylesheet's contents, which name each file
// it draws by the file's own fingerprint, so the path changes exactly when the stylesheet or a file
// it draws does and a browser may keep it for a year, a custom brand's changing with each stored
// color. A brand whose colors ColorsStylesheet cannot draw is an error.
func StylesheetPath(brand *record.Brand, slots brandasset.Slots) (string, error) {
	stylesheet, err := FullStylesheet(brand, slots)
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

// SafeStylesheetPath returns the path a page drawn in safe mode links brand's safe full stylesheet by,
// as StylesheetPath does the full one's: by its own route and the fingerprint of its own contents.
func SafeStylesheetPath(brand *record.Brand, slots brandasset.Slots) (string, error) {
	stylesheet, err := SafeFullStylesheet(brand, slots)
	if err != nil {
		return "", err
	}
	return linkPath(SafeStylesheetRoute, brand.Id, stylesheet), nil
}

// SafeColorsStylesheetPath returns the path of brand's safe colors-only stylesheet, as
// ColorsStylesheetPath does the colors-only one's.
func SafeColorsStylesheetPath(brand *record.Brand) (string, error) {
	stylesheet, err := SafeColorsStylesheet(brand)
	if err != nil {
		return "", err
	}
	return linkPath(SafeColorsStylesheetRoute, brand.Id, stylesheet), nil
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
	return colorsCSS(preset.Light, preset.Dark)
}

// colorsCSS sets every color token to its light value on the root and to its dark value under the
// two dark conditions, as stylesheetCSS describes. Each value must be a color.
func colorsCSS(light, dark map[string]string) string {
	declarations := func(colors map[string]string, indent string) string {
		var b strings.Builder
		for _, token := range tokens {
			b.WriteString(indent + "--color-" + token + ": " + colors[token] + ";\n")
		}
		return b.String()
	}
	return ":root {\n" + declarations(light, "  ") + "}\n" +
		"\n" +
		"@media (prefers-color-scheme: dark) {\n" +
		"  :root:not([data-theme=\"light\"]) {\n" + declarations(dark, "    ") + "  }\n" +
		"}\n" +
		"\n" +
		":root[data-theme=\"dark\"] {\n" + declarations(dark, "  ") + "}\n"
}
