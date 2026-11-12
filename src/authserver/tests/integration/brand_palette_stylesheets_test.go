package integration

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"regexp"
	"strconv"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/fake"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A custom brand's two stylesheets end to end (#815): a palette saved through the admin API draws
// the pages in its stored colors, light on the root and dark under the two dark selectors, a saved
// change moves both stylesheets' addresses, and a custom brand with no palette is drawn as a brand
// with an unknown theme.

// publishedStylesheets answers the two stylesheet URLs the public settings carry, empty when they
// carry no brand.
func publishedStylesheets(t *testing.T, browser *http.Client) (full, colors string) {
	t.Helper()
	status, settings, _ := getStylesheet(t, browser, appConfig.AuthServer.BaseURL+"/api/public/settings")
	require.Equal(t, http.StatusOK, status)
	var published struct {
		Brand *struct {
			StylesheetURL       string `json:"stylesheetUrl"`
			ColorsStylesheetURL string `json:"colorsStylesheetUrl"`
		} `json:"brand"`
	}
	require.NoError(t, json.Unmarshal([]byte(settings), &published))
	if published.Brand == nil {
		return "", ""
	}
	return published.Brand.StylesheetURL, published.Brand.ColorsStylesheetURL
}

func makeBrandDefault(t *testing.T, id int64) {
	t.Helper()
	ctx := context.Background()
	require.NoError(t, database.RunInTransaction(ctx, func(tx *sql.Tx) error {
		_, err := database.MakeBrandDefault(ctx, tx, id)
		return err
	}))
}

func TestBrandPaletteStylesheets_PagesAreDrawnInTheStoredColors(t *testing.T) {
	accessToken, _ := createAdminClientWithToken(t)
	_, created := keepDefaultBrand(t)
	base := appConfig.AuthServer.BaseURL
	browser := createHttpClient(t)

	// A basic palette: the light mode's other 19 colors are worked out at the save, and are the
	// probe's for the mid-gray brand color.
	name := brandName("Drawn")
	body := brandBody(map[string]any{"name": name, "appearance": "auto", "theme": "custom", "font": "serif",
		"palette": map[string]any{"mode": "basic", "light": paletteJSON(paletteMidGrayLight, basicTokens...),
			"dark": paletteJSON(paletteBlueberryDark, basicTokens...)}})
	status, answer, _ := brandCall(t, accessToken, http.MethodPost, brandsPath, body)
	require.Equal(t, http.StatusCreated, status, "create: %v", answer)
	id := int64(answer["brand"].(map[string]any)["id"].(float64))
	*created = append(*created, id)
	makeBrandDefault(t, id)
	idText := strconv.FormatInt(id, 10)

	full, colors := publishedStylesheets(t, browser)
	assert.Regexp(t, `^`+regexp.QuoteMeta(base)+`/brand/`+idText+`/stylesheet\.css\?v=[0-9a-f]{12}$`, full)
	assert.Regexp(t, `^`+regexp.QuoteMeta(base)+`/brand/`+idText+`/colors\.css\?v=[0-9a-f]{12}$`, colors)

	page := loadPage(t, browser, base+"/no-such-page-"+fake.LetterN(8))
	defer func() { _ = page.Body.Close() }()
	head := readBrandedPageHead(t, page)
	require.Len(t, head.stylesheets, 2, "main.css, then the brand's stylesheet")
	assert.Equal(t, full, base+head.stylesheets[1])

	for _, url := range []string{full, colors} {
		code, css, header := getStylesheet(t, browser, url)
		require.Equal(t, http.StatusOK, code, url)
		assert.Equal(t, "text/css; charset=utf-8", header.Get("Content-Type"))
		assert.Equal(t, "public, max-age=31536000, immutable", header.Get("Cache-Control"))
		// Light, on the root: an entered color and two worked out.
		assert.Contains(t, css, ":root {\n  --color-canvas: #f4f4f4;\n  --color-surface: #ffffff;\n  --color-subtle: #eeedeb;\n")
		assert.Contains(t, css, "  --color-ink-muted: #605e5a;\n  --color-brand: #777777;\n")
		// Dark, under both dark selectors.
		assert.Contains(t, css, "  :root:not([data-theme=\"light\"]) {\n    --color-canvas: #0f1217;\n")
		assert.Contains(t, css, ":root[data-theme=\"dark\"] {\n  --color-canvas: #0f1217;\n")
		assert.Contains(t, css, "  --color-brand-soft: #1b2a45;\n")
	}
	_, fullCSS, _ := getStylesheet(t, browser, full)
	_, colorsCSS, _ := getStylesheet(t, browser, colors)
	assert.Contains(t, fullCSS, "--font-sans: Charter")
	assert.NotContains(t, colorsCSS, "--font-")
	assert.Equal(t, fullCSS[:len(colorsCSS)], colorsCSS, "the full stylesheet is the colors, then the kit")

	// A saved change shows on the next page load: both addresses move, and the stylesheet answers
	// the new color.
	read := answer["brand"].(map[string]any)
	read["palette"].(map[string]any)["light"].(map[string]any)["brand"] = "#1F6B43"
	status, answer, _ = brandCall(t, accessToken, http.MethodPut, brandPath(id, ""), read)
	require.Equal(t, http.StatusOK, status, "update: %v", answer)

	changedFull, changedColors := publishedStylesheets(t, browser)
	assert.NotEqual(t, full, changedFull)
	assert.NotEqual(t, colors, changedColors)
	status, css, _ := getStylesheet(t, browser, changedColors)
	require.Equal(t, http.StatusOK, status)
	assert.Contains(t, css, "  --color-brand: #1f6b43;\n")
	assert.NotContains(t, css, "#777777")
}

// A custom brand with no palette, which only a hand edit of the database makes, is drawn as a brand
// with an unknown theme: its pages link main.css alone, the public settings carry no brand, and its
// stylesheets are a server fault.
func TestBrandPaletteStylesheets_ACustomBrandWithNoPaletteIsAnUnknownTheme(t *testing.T) {
	broken := record.NewBrand("Broken "+fake.LetterN(10), record.BrandAppearanceDark, record.BrandThemeCustom)
	brand := makeDefaultBrandOf(t, &broken)
	base := appConfig.AuthServer.BaseURL
	browser := createHttpClient(t)
	id := strconv.FormatInt(brand.Id, 10)

	page := loadPage(t, browser, base+"/no-such-page-"+fake.LetterN(8))
	defer func() { _ = page.Body.Close() }()
	head := readBrandedPageHead(t, page)
	assert.False(t, head.hasDataTheme, "got data-theme %q", head.dataTheme)
	require.Len(t, head.stylesheets, 1, "main.css alone")

	full, colors := publishedStylesheets(t, browser)
	assert.Empty(t, full)
	assert.Empty(t, colors)

	for _, path := range []string{"/brand/" + id + "/stylesheet.css", "/brand/" + id + "/colors.css"} {
		status, css, _ := getStylesheet(t, browser, base+path)
		assert.Equal(t, http.StatusInternalServerError, status, path)
		assert.NotContains(t, css, "--color-", path)
	}
}
