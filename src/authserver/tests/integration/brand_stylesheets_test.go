package integration

import (
	"encoding/json"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/fake"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A brand's two stylesheets end to end (#813 decision 9): the full one, which the auth server's
// pages link, sets the colors, the corners and the font; the colors-only one sets the colors alone.
// The public settings name both, and each is answered to anyone, kept for a year by its current
// fingerprint, with no cookie.

// getStylesheet loads url, a stylesheet or the public settings, and answers its status, its body and
// its headers.
func getStylesheet(t *testing.T, browser *http.Client, url string) (int, string, http.Header) {
	t.Helper()
	resp, err := browser.Get(url)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	return resp.StatusCode, string(body), resp.Header
}

func TestBrandStylesheets_TheFullOneDrawsTheKitAndTheColorsOneTheColorsAlone(t *testing.T) {
	kit := record.NewBrand("Kit "+fake.LetterN(10), record.BrandAppearanceDark, "plum")
	kit.Corners = record.BrandCornersPill
	kit.Font = record.BrandFontSerif
	brand := makeDefaultBrandOf(t, &kit)
	base := appConfig.AuthServer.BaseURL
	browser := createHttpClient(t)
	id := strconv.FormatInt(brand.Id, 10)

	status, settings, _ := getStylesheet(t, browser, base+"/api/public/settings")
	require.Equal(t, http.StatusOK, status)
	var published struct {
		Brand struct {
			StylesheetURL       string `json:"stylesheetUrl"`
			ColorsStylesheetURL string `json:"colorsStylesheetUrl"`
		} `json:"brand"`
	}
	require.NoError(t, json.Unmarshal([]byte(settings), &published))
	assert.Regexp(t, `^`+regexp.QuoteMeta(base)+`/brand/`+id+`/stylesheet\.css\?v=[0-9a-f]{12}$`, published.Brand.StylesheetURL)
	assert.Regexp(t, `^`+regexp.QuoteMeta(base)+`/brand/`+id+`/colors\.css\?v=[0-9a-f]{12}$`, published.Brand.ColorsStylesheetURL)

	// The auth server's own pages link the full one.
	page := loadPage(t, browser, base+"/no-such-page-"+fake.LetterN(8))
	defer func() { _ = page.Body.Close() }()
	head := readBrandedPageHead(t, page)
	require.Len(t, head.stylesheets, 2, "main.css, then the brand's stylesheet")
	assert.Equal(t, published.Brand.StylesheetURL, base+head.stylesheets[1])

	status, full, header := getStylesheet(t, browser, published.Brand.StylesheetURL)
	require.Equal(t, http.StatusOK, status)
	assert.Equal(t, "text/css; charset=utf-8", header.Get("Content-Type"))
	assert.Equal(t, "public, max-age=31536000, immutable", header.Get("Cache-Control"))
	assert.Empty(t, header.Values("Set-Cookie"))
	assert.Contains(t, full, "--color-brand: #7a3aa8;")
	assert.Contains(t, full, "  --radius-control: 9999px;\n  --radius-panel: 1.5rem;\n")
	assert.Contains(t, full, "  --font-sans: Charter, 'Bitstream Charter', 'Sitka Text', Cambria, serif;\n")

	status, colors, header := getStylesheet(t, browser, published.Brand.ColorsStylesheetURL)
	require.Equal(t, http.StatusOK, status)
	assert.Equal(t, "text/css; charset=utf-8", header.Get("Content-Type"))
	assert.Equal(t, "public, max-age=31536000, immutable", header.Get("Cache-Control"))
	assert.Empty(t, header.Values("Set-Cookie"))
	assert.Contains(t, colors, "--color-brand: #7a3aa8;")
	assert.Contains(t, colors, "--color-brand: #cda4f0;")
	assert.NotContains(t, colors, "--radius-")
	assert.NotContains(t, colors, "--font-")
	assert.Equal(t, full[:len(colors)], colors, "the full stylesheet is the colors, then the kit")

	// An unknown brand has neither.
	status, _, _ = getStylesheet(t, browser, base+"/brand/999999999/colors.css")
	assert.Equal(t, http.StatusNotFound, status)
}
