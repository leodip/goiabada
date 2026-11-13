package handlers

import (
	"net/http"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/brandasset"
	"github.com/leodip/goiabada/authserver/internal/brandthemes"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A brand's custom CSS goes last in its full stylesheet and nowhere else (#816): after its colors
// and its kit, as it was stored, so it reaches every page linking that stylesheet, moves the
// stylesheet's address, and never reaches the colors-only stylesheet the console's admin pages
// link.

const (
	// blueberryStylesheet is the colors stylesheet of a Blueberry brand, which declares no colors.
	blueberryStylesheet = "/* Blueberry is the palette main.css is built with: this stylesheet declares no colors. */\n"
	// cardCSS is custom CSS as an administrator writes it, with no line feed at its end.
	cardCSS = "body[data-page=\"sign-in\"] .auth-card {\n  border: 2px solid var(--color-brand);\n}"
)

// A brand nobody has given a kit, with custom CSS: its colors, then the CSS as stored.
func TestBrandStylesheets_TheCustomCSSFollowsTheColors(t *testing.T) {
	brand := themedBrand(7, "blueberry")
	brand.CustomCSS = cardCSS
	want := blueberryStylesheet + "\n" + cardCSS

	full, err := brandthemes.StylesheetPath(brand, brandasset.Slots{})
	require.NoError(t, err)
	assert.Equal(t, "/brand/7/stylesheet.css?v="+fingerprintOf(want), full)
	rr := getBrandStylesheet(t, full, brand)
	require.Equal(t, http.StatusOK, rr.Code)
	assert.Equal(t, yearCache, rr.Header().Get("Cache-Control"))
	assert.Equal(t, want, rr.Body.String())

	colors, err := brandthemes.ColorsStylesheetPath(brand)
	require.NoError(t, err)
	assert.Equal(t, "/brand/7/colors.css?v="+fingerprintOf(blueberryStylesheet), colors)
	rr = getColorsStylesheet(t, colors, brand)
	require.Equal(t, http.StatusOK, rr.Code)
	assert.Equal(t, blueberryStylesheet, rr.Body.String(), "the colors-only stylesheet never carries the CSS")
}

// With a theme's colors and a kit, the CSS comes after both, and the colors-only stylesheet keeps
// the colors alone.
func TestBrandStylesheets_TheCustomCSSFollowsTheKit(t *testing.T) {
	brand := kitBrand("avocado", record.BrandCornersPill, record.BrandFontSerif)
	brand.CustomCSS = cardCSS + "\n"

	full := getBrandStylesheet(t, "/brand/7/stylesheet.css", brand)
	require.Equal(t, http.StatusOK, full.Code)
	assert.Equal(t, avocadoStylesheet+"\n:root {\n  --radius-control: 9999px;\n  --radius-panel: 1.5rem;\n"+
		"  --font-sans: Charter, 'Bitstream Charter', 'Sitka Text', Cambria, serif;\n}\n"+
		"\n"+cardCSS+"\n", full.Body.String())

	colors := getColorsStylesheet(t, "/brand/7/colors.css", brand)
	require.Equal(t, http.StatusOK, colors.Code)
	assert.Equal(t, avocadoStylesheet, colors.Body.String())
}

// A saved change of the CSS shows on the next page load: the full stylesheet's address moves, and
// the colors-only one's stays.
func TestBrandStylesheets_ChangedCustomCSSChangesTheFullAddressOnly(t *testing.T) {
	addresses := func(css string) (string, string) {
		brand := themedBrand(7, "plum")
		brand.CustomCSS = css
		full, err := brandthemes.StylesheetPath(brand, brandasset.Slots{})
		require.NoError(t, err)
		colors, err := brandthemes.ColorsStylesheetPath(brand)
		require.NoError(t, err)
		return full, colors
	}
	noneFull, noneColors := addresses("")
	oneFull, oneColors := addresses(".auth-card { border-width: 3px; }")
	otherFull, otherColors := addresses(".auth-card { border-width: 4px; }")

	assert.NotEqual(t, noneFull, oneFull)
	assert.NotEqual(t, oneFull, otherFull)
	assert.Equal(t, noneColors, oneColors)
	assert.Equal(t, oneColors, otherColors)
}
