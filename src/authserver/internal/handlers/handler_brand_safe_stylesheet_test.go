package handlers

import (
	"database/sql"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/authserver/internal/brandasset"
	"github.com/leodip/goiabada/authserver/internal/brandthemes"
	"github.com/leodip/goiabada/authserver/internal/data/mocks"
	"github.com/leodip/goiabada/authserver/internal/handlers/mocks"
	"github.com/leodip/goiabada/authserver/internal/record"
)

// A brand's two safe stylesheets draw it without what an administrator authors freely (#816
// decision 1): no custom CSS, Blueberry's colors in place of a custom palette, and the System UI
// family in place of an uploaded font. Everything else is drawn as the brand's own stylesheets draw
// it: a built-in theme's colors, the corners, a system family and the background.

// getSafeStylesheet requests target from the safe full stylesheet's handler, the brand of id 7 being
// brand, whose slots name assets, read by their ids in slot order, or none when ids is nil.
func getSafeStylesheet(t *testing.T, target string, brand *record.Brand, ids []int64,
	assets []record.BrandAsset) *httptest.ResponseRecorder {
	t.Helper()
	database := datamocks.NewDatabase(t)
	database.On("GetBrandById", mock.Anything, (*sql.Tx)(nil), int64(7)).Return(brand, nil).Once()
	if ids != nil {
		database.On("GetBrandAssetsByIds", mock.Anything, (*sql.Tx)(nil), ids).Return(assets, nil).Once()
	}

	req := withPathValue(httptest.NewRequest(http.MethodGet, target, nil), "id", "7")
	rr := httptest.NewRecorder()
	HandleBrandSafeStylesheetGet(handlersmocks.NewPageRenderer(t), database).ServeHTTP(rr, req)
	return rr
}

// getSafeColorsStylesheet requests target from the safe colors-only stylesheet's handler, which
// reads no asset.
func getSafeColorsStylesheet(t *testing.T, target string, brand *record.Brand) *httptest.ResponseRecorder {
	t.Helper()
	return getStylesheetFrom(t, HandleBrandSafeColorsStylesheetGet, target, brand)
}

// allThreeBrand is a brand holding all three things safe mode sets aside, custom CSS, a custom
// palette and an uploaded font in two files, beside square corners and a tiled background, which
// it keeps.
func allThreeBrand() (*record.Brand, []int64, []record.BrandAsset) {
	brand := customBrand(record.BrandPaletteModeAdvanced, customLight, customDark)
	brand.Corners, brand.Font = record.BrandCornersSquare, record.BrandFontUploaded
	brand.CustomCSS = cardCSS
	brand.BackgroundFit = "tile"
	brand.BackgroundAssetId = sql.NullInt64{Int64: 14, Valid: true}
	brand.RegularFontAssetId = sql.NullInt64{Int64: 15, Valid: true}
	brand.BoldFontAssetId = sql.NullInt64{Int64: 16, Valid: true}
	return brand, []int64{14, 15, 16}, []record.BrandAsset{
		kitAsset(14, record.BrandAssetKindBackground, "0a1b2c3d4e5f"),
		kitAsset(15, record.BrandAssetKindFont, "aaaaaaaaaaaa"),
		kitAsset(16, record.BrandAssetKindFont, "bbbbbbbbbbbb"),
	}
}

// squareTiledKit is the kit part of a stylesheet drawing square corners and the background of id 14
// tiled, as the full stylesheet draws them.
const squareTiledKit = ":root {\n" +
	"  --radius-control: 0;\n" +
	"  --radius-panel: 0;\n" +
	"}\n" +
	"\n" +
	".auth-page {\n" +
	"  background-image: url(\"/brand-assets/14?v=0a1b2c3d4e5f\");\n" +
	"  background-repeat: repeat;\n" +
	"}\n"

// A brand holding all three is drawn safe in Blueberry, its corners and its background, with no
// font file, no family and no custom CSS; its safe colors-only stylesheet is Blueberry's.
func TestBrandSafeStylesheets_SetAsideTheCSSThePaletteAndTheUploadedFont(t *testing.T) {
	brand, ids, assets := allThreeBrand()
	want := blueberryNote + "\n" + squareTiledKit

	rr := getSafeStylesheet(t, "/brand/7/safe-stylesheet.css", brand, ids, assets)
	require.Equal(t, http.StatusOK, rr.Code)
	assert.Equal(t, "text/css; charset=utf-8", rr.Header().Get("Content-Type"))
	assert.Equal(t, want, rr.Body.String())

	rr = getSafeColorsStylesheet(t, "/brand/7/safe-colors.css", brand)
	require.Equal(t, http.StatusOK, rr.Code)
	assert.Equal(t, "text/css; charset=utf-8", rr.Header().Get("Content-Type"))
	assert.Equal(t, blueberryNote, rr.Body.String())

	// Nothing stored changes: the brand's own stylesheets still draw all three.
	full := getFullStylesheetWithAssets(t, "/brand/7/stylesheet.css", brand, ids, assets)
	require.Equal(t, http.StatusOK, full.Code)
	assert.Contains(t, full.Body.String(), "--color-brand: #777777;")
	assert.Contains(t, full.Body.String(), "@font-face")
	assert.Contains(t, full.Body.String(), cardCSS)
}

// A brand on a built-in theme with a system family and none of the three is drawn the same in and
// out of safe mode: its colors, its corners, its family and its background.
func TestBrandSafeStylesheets_ABuiltInBrandWithNoneOfTheThreeIsDrawnAsUsual(t *testing.T) {
	brand := kitBrand("avocado", record.BrandCornersPill, record.BrandFontSerif)
	brand.BackgroundFit = "tile"
	brand.BackgroundAssetId = sql.NullInt64{Int64: 14, Valid: true}
	ids := []int64{14}
	assets := []record.BrandAsset{kitAsset(14, record.BrandAssetKindBackground, "0a1b2c3d4e5f")}
	want := avocadoStylesheet + "\n" +
		":root {\n" +
		"  --radius-control: 9999px;\n" +
		"  --radius-panel: 1.5rem;\n" +
		"  --font-sans: Charter, 'Bitstream Charter', 'Sitka Text', Cambria, serif;\n" +
		"}\n" +
		"\n" +
		".auth-page {\n" +
		"  background-image: url(\"/brand-assets/14?v=0a1b2c3d4e5f\");\n" +
		"  background-repeat: repeat;\n" +
		"}\n"

	safe := getSafeStylesheet(t, "/brand/7/safe-stylesheet.css", brand, ids, assets)
	require.Equal(t, http.StatusOK, safe.Code)
	assert.Equal(t, want, safe.Body.String())

	full := getFullStylesheetWithAssets(t, "/brand/7/stylesheet.css", brand, ids, assets)
	require.Equal(t, http.StatusOK, full.Code)
	assert.Equal(t, want, full.Body.String())

	safeColors := getSafeColorsStylesheet(t, "/brand/7/safe-colors.css", brand)
	require.Equal(t, http.StatusOK, safeColors.Code)
	assert.Equal(t, avocadoStylesheet, safeColors.Body.String())
}

// A brand on a built-in theme keeps its theme's colors in safe mode, and loses its custom CSS and its
// uploaded font: with rounded corners nothing else is drawn, so its safe stylesheet is its colors.
func TestBrandSafeStylesheets_ABuiltInBrandKeepsItsColorsAndLosesTheCSSAndTheFont(t *testing.T) {
	brand := kitBrand("avocado", record.BrandCornersRounded, record.BrandFontUploaded)
	brand.CustomCSS = cardCSS
	brand.RegularFontAssetId = sql.NullInt64{Int64: 15, Valid: true}
	ids := []int64{15}
	assets := []record.BrandAsset{kitAsset(15, record.BrandAssetKindFont, "aaaaaaaaaaaa")}

	rr := getSafeStylesheet(t, "/brand/7/safe-stylesheet.css", brand, ids, assets)
	require.Equal(t, http.StatusOK, rr.Code)
	assert.Equal(t, avocadoStylesheet, rr.Body.String())
}

// Each safe stylesheet is linked by its own route and the fingerprint of its own contents, kept a
// year by it, and five minutes by any other.
func TestBrandSafeStylesheetPaths_NameTheirRouteAndTheirContents(t *testing.T) {
	brand, ids, assets := allThreeBrand()
	slots := brandasset.Slots{Background: &assets[0], RegularFont: &assets[1], BoldFont: &assets[2]}

	safe, err := brandthemes.SafeStylesheetPath(brand, slots)
	require.NoError(t, err)
	assert.Equal(t, "/brand/7/safe-stylesheet.css?v="+fingerprintOf(blueberryNote+"\n"+squareTiledKit), safe)
	safeColors, err := brandthemes.SafeColorsStylesheetPath(brand)
	require.NoError(t, err)
	assert.Equal(t, "/brand/7/safe-colors.css?v="+fingerprintOf(blueberryNote), safeColors)

	full, err := brandthemes.StylesheetPath(brand, slots)
	require.NoError(t, err)
	assert.NotEqual(t, safe, full)

	rr := getSafeStylesheet(t, safe, brand, ids, assets)
	require.Equal(t, http.StatusOK, rr.Code)
	assert.Equal(t, yearCache, rr.Header().Get("Cache-Control"))
	rr = getSafeStylesheet(t, "/brand/7/safe-stylesheet.css?v=000000000000", brand, ids, assets)
	require.Equal(t, http.StatusOK, rr.Code)
	assert.Equal(t, fiveMinuteCache, rr.Header().Get("Cache-Control"))

	rr = getSafeColorsStylesheet(t, safeColors, brand)
	require.Equal(t, http.StatusOK, rr.Code)
	assert.Equal(t, yearCache, rr.Header().Get("Cache-Control"))
	rr = getSafeColorsStylesheet(t, "/brand/7/safe-colors.css", brand)
	require.Equal(t, http.StatusOK, rr.Code)
	assert.Equal(t, fiveMinuteCache, rr.Header().Get("Cache-Control"))
}

// A custom brand whose palette cannot be drawn, which only a hand edit of the database makes, has no
// stylesheet of its own, and is still drawn safe in Blueberry: safe mode never reads the palette.
func TestBrandSafeStylesheets_ACustomBrandWithNoPaletteIsDrawnInBlueberry(t *testing.T) {
	brand := customBrand(record.BrandPaletteModeBasic, customLight, customDark)
	brand.Palette = nil

	rr := getSafeColorsStylesheet(t, "/brand/7/safe-colors.css", brand)
	require.Equal(t, http.StatusOK, rr.Code)
	assert.Equal(t, blueberryNote, rr.Body.String())

	rr = getSafeStylesheet(t, "/brand/7/safe-stylesheet.css", brand, nil, nil)
	require.Equal(t, http.StatusOK, rr.Code)
	assert.Equal(t, blueberryNote, rr.Body.String())
}

// A brand that does not exist has no safe stylesheet.
func TestBrandSafeStylesheets_ABrandThatDoesNotExistIsNotFound(t *testing.T) {
	rr := getSafeStylesheet(t, "/brand/7/safe-stylesheet.css", nil, nil, nil)
	assert.Equal(t, http.StatusNotFound, rr.Code)
	rr = getSafeColorsStylesheet(t, "/brand/7/safe-colors.css", nil)
	assert.Equal(t, http.StatusNotFound, rr.Code)
}
