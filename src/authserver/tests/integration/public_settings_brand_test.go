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

// /api/public/settings carries the default brand, which the admin console draws every page in: its
// appearance, and the absolute URL of its stylesheet, which the console links as given (#810
// decision 3). The URL is the one the auth server's own pages link, so the console and the auth
// server draw in one stylesheet, loaded from one place.
func TestPublicSettings_CarriesTheDefaultBrandsStylesheet(t *testing.T) {
	brand := makeDefaultBrand(t, record.BrandAppearanceDark, "plum")
	base := appConfig.AuthServer.BaseURL
	browser := createHttpClient(t)

	resp, err := browser.Get(base + "/api/public/settings")
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	var published map[string]json.RawMessage
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&published))
	assert.NotContains(t, published, "uiTheme")
	var publishedBrand struct {
		Appearance    string `json:"appearance"`
		StylesheetURL string `json:"stylesheetUrl"`
	}
	require.NoError(t, json.Unmarshal(published["brand"], &publishedBrand))
	assert.Equal(t, "dark", publishedBrand.Appearance)
	assert.Regexp(t, `^`+regexp.QuoteMeta(base)+`/brand/`+strconv.FormatInt(brand.Id, 10)+`/stylesheet\.css\?v=[0-9a-f]{12}$`,
		publishedBrand.StylesheetURL)

	// It is the URL the auth server's own pages link, relative there.
	page := loadPage(t, browser, base+"/no-such-page-"+fake.LetterN(8))
	defer func() { _ = page.Body.Close() }()
	head := readBrandedPageHead(t, page)
	require.Len(t, head.stylesheets, 2, "main.css, then the brand's stylesheet")
	assert.Equal(t, base+head.stylesheets[1], publishedBrand.StylesheetURL)

	// And it loads: Plum's colors, cacheable for a year.
	stylesheet, err := browser.Get(publishedBrand.StylesheetURL)
	require.NoError(t, err)
	defer func() { _ = stylesheet.Body.Close() }()
	body, err := io.ReadAll(stylesheet.Body)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, stylesheet.StatusCode)
	assert.Equal(t, "public, max-age=31536000, immutable", stylesheet.Header.Get("Cache-Control"))
	assert.Contains(t, string(body), "--color-brand: #7a3aa8;")
	assert.Contains(t, string(body), "--color-brand: #cda4f0;")
}

// An automatic brand is published as auto, not as an empty value.
func TestPublicSettings_CarriesAnAutomaticDefaultBrandAsAuto(t *testing.T) {
	makeDefaultBrand(t, record.BrandAppearanceAuto, "coconut")

	resp, err := createHttpClient(t).Get(appConfig.AuthServer.BaseURL + "/api/public/settings")
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	var published struct {
		Brand struct {
			Appearance string `json:"appearance"`
		} `json:"brand"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&published))
	assert.Equal(t, "auto", published.Brand.Appearance)
}
