package handlers

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"maps"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/brandasset"
	"github.com/leodip/goiabada/authserver/internal/brandthemes"
	"github.com/leodip/goiabada/authserver/internal/data/mocks"
	"github.com/leodip/goiabada/authserver/internal/handlers/mocks"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// A custom brand's two stylesheets are drawn from its stored palette (#815): its 23 light colors on
// the root and its 23 dark ones under the two conditions ui.css's dark variant applies the dark
// palette on, as a built-in theme's are.

// customLight and customDark are a stored palette's two modes: the probe's "mid-gray brand color"
// worked out in light, and Blueberry's dark mode worked out from its own four colors.
var customLight = map[string]string{"canvas": "#f4f4f4", "surface": "#ffffff", "subtle": "#eeedeb", "line": "#dcdad4",
	"line-strong": "#7d796c", "ink": "#222222", "ink-muted": "#605e5a", "brand": "#777777", "brand-strong": "#606060",
	"on-brand": "#ffffff", "brand-soft": "#ececec", "danger": "#b42318", "danger-strong": "#8f1c13", "on-danger": "#ffffff",
	"danger-soft": "#fdeceb", "danger-ink": "#8f1c13", "positive-soft": "#e3f3e8", "positive-ink": "#17612f",
	"caution-soft": "#fdf2d6", "caution-ink": "#6b4400", "note-soft": "#e6edfb", "note-ink": "#1d4796", "focus": "#777777"}

var customDark = map[string]string{"canvas": "#0f1217", "surface": "#171b22", "subtle": "#1f242d", "line": "#2e3541",
	"line-strong": "#6e798e", "ink": "#e6e8ec", "ink-muted": "#a4a8b0", "brand": "#8ab4ff", "brand-strong": "#abcaff",
	"on-brand": "#0c1a33", "brand-soft": "#1b2a45", "danger": "#ff8f85", "danger-strong": "#ffb0a8", "on-danger": "#330b07",
	"danger-soft": "#3a1714", "danger-ink": "#ffb4ab", "positive-soft": "#11291a", "positive-ink": "#8fd6a5",
	"caution-soft": "#2e2410", "caution-ink": "#f0c96a", "note-soft": "#142340", "note-ink": "#a8c7ff", "focus": "#8ab4ff"}

// customStylesheet is the colors stylesheet of a brand on customLight and customDark, written out by
// hand: every token in ui.css's order, light on the root, dark under the two dark selectors.
const customStylesheet = `:root {
  --color-canvas: #f4f4f4;
  --color-surface: #ffffff;
  --color-subtle: #eeedeb;
  --color-line: #dcdad4;
  --color-line-strong: #7d796c;
  --color-ink: #222222;
  --color-ink-muted: #605e5a;
  --color-brand: #777777;
  --color-brand-strong: #606060;
  --color-on-brand: #ffffff;
  --color-brand-soft: #ececec;
  --color-danger: #b42318;
  --color-danger-strong: #8f1c13;
  --color-on-danger: #ffffff;
  --color-danger-soft: #fdeceb;
  --color-danger-ink: #8f1c13;
  --color-positive-soft: #e3f3e8;
  --color-positive-ink: #17612f;
  --color-caution-soft: #fdf2d6;
  --color-caution-ink: #6b4400;
  --color-note-soft: #e6edfb;
  --color-note-ink: #1d4796;
  --color-focus: #777777;
}

@media (prefers-color-scheme: dark) {
  :root:not([data-theme="light"]) {
    --color-canvas: #0f1217;
    --color-surface: #171b22;
    --color-subtle: #1f242d;
    --color-line: #2e3541;
    --color-line-strong: #6e798e;
    --color-ink: #e6e8ec;
    --color-ink-muted: #a4a8b0;
    --color-brand: #8ab4ff;
    --color-brand-strong: #abcaff;
    --color-on-brand: #0c1a33;
    --color-brand-soft: #1b2a45;
    --color-danger: #ff8f85;
    --color-danger-strong: #ffb0a8;
    --color-on-danger: #330b07;
    --color-danger-soft: #3a1714;
    --color-danger-ink: #ffb4ab;
    --color-positive-soft: #11291a;
    --color-positive-ink: #8fd6a5;
    --color-caution-soft: #2e2410;
    --color-caution-ink: #f0c96a;
    --color-note-soft: #142340;
    --color-note-ink: #a8c7ff;
    --color-focus: #8ab4ff;
  }
}

:root[data-theme="dark"] {
  --color-canvas: #0f1217;
  --color-surface: #171b22;
  --color-subtle: #1f242d;
  --color-line: #2e3541;
  --color-line-strong: #6e798e;
  --color-ink: #e6e8ec;
  --color-ink-muted: #a4a8b0;
  --color-brand: #8ab4ff;
  --color-brand-strong: #abcaff;
  --color-on-brand: #0c1a33;
  --color-brand-soft: #1b2a45;
  --color-danger: #ff8f85;
  --color-danger-strong: #ffb0a8;
  --color-on-danger: #330b07;
  --color-danger-soft: #3a1714;
  --color-danger-ink: #ffb4ab;
  --color-positive-soft: #11291a;
  --color-positive-ink: #8fd6a5;
  --color-caution-soft: #2e2410;
  --color-caution-ink: #f0c96a;
  --color-note-soft: #142340;
  --color-note-ink: #a8c7ff;
  --color-focus: #8ab4ff;
}
`

// customBrand is the brand of id 7 on the custom theme with a palette of mode holding light and dark,
// each a copy, and the kit an existing brand has.
func customBrand(mode record.BrandPaletteMode, light, dark map[string]string) *record.Brand {
	brand := themedBrand(7, record.BrandThemeCustom)
	brand.Palette = &record.BrandPalette{Mode: mode, Light: maps.Clone(light), Dark: maps.Clone(dark)}
	return brand
}

func fingerprintOf(css string) string {
	digest := sha256.Sum256([]byte(css))
	return hex.EncodeToString(digest[:])[:12]
}

// Both stylesheets of a custom brand declare its 46 stored colors, whichever mode made the palette
// and whatever its appearance, and nothing else for a brand nobody has given a kit. Each is linked
// by the fingerprint of its contents and kept for a year by it.
func TestBrandStylesheets_ACustomBrandIsDrawnInItsStoredColors(t *testing.T) {
	for _, mode := range []record.BrandPaletteMode{record.BrandPaletteModeBasic, record.BrandPaletteModeAdvanced} {
		for _, appearance := range []record.BrandAppearance{record.BrandAppearanceAuto, record.BrandAppearanceLight, record.BrandAppearanceDark} {
			t.Run(string(mode)+" "+string(appearance), func(t *testing.T) {
				brand := customBrand(mode, customLight, customDark)
				brand.Appearance = appearance

				full, err := brandthemes.StylesheetPath(brand, brandasset.Slots{})
				require.NoError(t, err)
				assert.Equal(t, "/brand/7/stylesheet.css?v="+fingerprintOf(customStylesheet), full)
				colors, err := brandthemes.ColorsStylesheetPath(brand)
				require.NoError(t, err)
				assert.Equal(t, "/brand/7/colors.css?v="+fingerprintOf(customStylesheet), colors)

				rr := getBrandStylesheet(t, full, brand)
				require.Equal(t, http.StatusOK, rr.Code)
				assert.Equal(t, "text/css; charset=utf-8", rr.Header().Get("Content-Type"))
				assert.Equal(t, yearCache, rr.Header().Get("Cache-Control"))
				assert.Equal(t, customStylesheet, rr.Body.String())

				rr = getColorsStylesheet(t, colors, brand)
				require.Equal(t, http.StatusOK, rr.Code)
				assert.Equal(t, yearCache, rr.Header().Get("Cache-Control"))
				assert.Equal(t, customStylesheet, rr.Body.String())
			})
		}
	}
}

// A custom brand's kit is drawn after its colors in the full stylesheet, as a built-in theme's is,
// and the colors-only one keeps the colors alone.
func TestBrandStylesheets_ACustomBrandsKitFollowsItsColors(t *testing.T) {
	brand := customBrand(record.BrandPaletteModeAdvanced, customLight, customDark)
	brand.Corners, brand.Font = record.BrandCornersPill, record.BrandFontSerif

	full := getBrandStylesheet(t, "/brand/7/stylesheet.css", brand)
	require.Equal(t, http.StatusOK, full.Code)
	assert.Equal(t, customStylesheet+"\n:root {\n  --radius-control: 9999px;\n  --radius-panel: 1.5rem;\n"+
		"  --font-sans: Charter, 'Bitstream Charter', 'Sitka Text', Cambria, serif;\n}\n", full.Body.String())

	colors := getColorsStylesheet(t, "/brand/7/colors.css", brand)
	require.Equal(t, http.StatusOK, colors.Code)
	assert.Equal(t, customStylesheet, colors.Body.String())
}

// A saved change shows on the next page load: changing one color, light or dark, changes both
// stylesheets' addresses, and the stylesheet answers the new color where the old one was.
func TestBrandStylesheets_AChangedColorChangesTheAddress(t *testing.T) {
	before := customBrand(record.BrandPaletteModeAdvanced, customLight, customDark)
	beforeFull, err := brandthemes.StylesheetPath(before, brandasset.Slots{})
	require.NoError(t, err)
	beforeColors, err := brandthemes.ColorsStylesheetPath(before)
	require.NoError(t, err)

	for _, tc := range []struct {
		name   string
		change func(*record.Brand)
		old    string
		new    string
	}{
		{"light", func(b *record.Brand) { b.Palette.Light["note-ink"] = "#1d4797" },
			"  --color-note-ink: #1d4796;\n", "  --color-note-ink: #1d4797;\n"},
		{"dark", func(b *record.Brand) { b.Palette.Dark["focus"] = "#8ab4fe" },
			// Under both dark selectors.
			"--color-focus: #8ab4ff;\n", "--color-focus: #8ab4fe;\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			after := customBrand(record.BrandPaletteModeAdvanced, customLight, customDark)
			tc.change(after)

			afterFull, err := brandthemes.StylesheetPath(after, brandasset.Slots{})
			require.NoError(t, err)
			afterColors, err := brandthemes.ColorsStylesheetPath(after)
			require.NoError(t, err)
			assert.NotEqual(t, beforeFull, afterFull)
			assert.NotEqual(t, beforeColors, afterColors)

			rr := getColorsStylesheet(t, afterColors, after)
			require.Equal(t, http.StatusOK, rr.Code)
			assert.Equal(t, yearCache, rr.Header().Get("Cache-Control"))
			assert.Equal(t, strings.ReplaceAll(customStylesheet, tc.old, tc.new), rr.Body.String())
		})
	}
}

// A custom brand whose palette cannot be drawn, which only a hand edit of the database makes, is a
// brand with an unknown theme: each stylesheet is a server fault naming the brand, and no path links
// one. That is no palette at all, a mode with a token missing, and a value that is not a #rrggbb
// color, whatever it would have smuggled into the stylesheet.
func TestBrandStylesheets_ACustomPaletteThatCannotBeDrawnIsAnUnknownTheme(t *testing.T) {
	without := func(colors map[string]string, token string) map[string]string {
		changed := maps.Clone(colors)
		delete(changed, token)
		return changed
	}
	with := func(colors map[string]string, token, value string) map[string]string {
		changed := maps.Clone(colors)
		changed[token] = value
		return changed
	}
	noPalette := themedBrand(7, record.BrandThemeCustom)

	for _, tc := range []struct {
		name  string
		brand *record.Brand
	}{
		{"no palette", noPalette},
		{"no light ink", customBrand(record.BrandPaletteModeAdvanced, without(customLight, "ink"), customDark)},
		{"no dark focus", customBrand(record.BrandPaletteModeBasic, customLight, without(customDark, "focus"))},
		{"no light colors", customBrand(record.BrandPaletteModeAdvanced, nil, customDark)},
		{"a rule smuggled into a light color", customBrand(record.BrandPaletteModeAdvanced,
			with(customLight, "brand", "#777777; } body { display: none"), customDark)},
		{"a dark color that is a name", customBrand(record.BrandPaletteModeAdvanced, customLight, with(customDark, "canvas", "black"))},
		{"a three-digit dark color", customBrand(record.BrandPaletteModeAdvanced, customLight, with(customDark, "line", "#fff"))},
		{"an empty light color", customBrand(record.BrandPaletteModeBasic, with(customLight, "on-brand", ""), customDark)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := brandthemes.StylesheetPath(tc.brand, brandasset.Slots{})
			require.Error(t, err)
			_, err = brandthemes.ColorsStylesheetPath(tc.brand)
			require.Error(t, err)

			for _, handler := range []struct {
				route string
				serve func(PageRenderer, brandStylesheetDatabase) http.HandlerFunc
			}{
				{"/brand/7/stylesheet.css", HandleBrandStylesheetGet},
				{"/brand/7/colors.css", HandleBrandColorsStylesheetGet},
			} {
				database := datamocks.NewDatabase(t)
				database.On("GetBrandById", mock.Anything, (*sql.Tx)(nil), int64(7)).Return(tc.brand, nil).Once()
				pageRenderer := handlersmocks.NewPageRenderer(t)
				pageRenderer.On("InternalServerError", mock.Anything, mock.Anything, mock.MatchedBy(func(err error) bool {
					return strings.Contains(err.Error(), "brand 7")
				})).Once()
				req := withPathValue(httptest.NewRequest(http.MethodGet, handler.route, nil), "id", "7")
				rr := httptest.NewRecorder()

				handler.serve(pageRenderer, database).ServeHTTP(rr, req)

				assert.NotContains(t, rr.Body.String(), "--color-", handler.route)
			}
		})
	}
}
