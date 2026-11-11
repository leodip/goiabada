package integration

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/PuerkitoBio/goquery"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A brand's kit end to end (#813 decisions 4 to 7, 9 and 10): files uploaded as brand assets, named
// in a brand's six slots through the admin API and stored on the engine's foreign keys, then drawn by
// the auth server: the logo and the name on a card, the favicon in the head, the background and the
// uploaded font in the full stylesheet, and the images and the switch in the public settings.

// kitUploads are one stored asset per slot, uploaded through the admin API.
type kitUploads struct {
	logo, darkLogo, favicon, background, regularFont, boldFont brandAssetAnswer
}

func uploadKit(t *testing.T, accessToken string) kitUploads {
	t.Helper()
	upload := func(kind string, data []byte) brandAssetAnswer {
		resp, _ := uploadBrandAsset(t, accessToken, kind, data)
		require.Equal(t, http.StatusCreated, resp.StatusCode, kind)
		return decodeBrandAsset(t, resp)
	}
	return kitUploads{
		logo:        upload("logo", createTestPNGImage(240, 80)),
		darkLogo:    upload("logo", brandJPEG(240, 80)),
		favicon:     upload("favicon", createTestPNGImage(64, 64)),
		background:  upload("background", brandJPEG(800, 600)),
		regularFont: upload("font", brandWOFF2(1024)),
		boldFont:    upload("font", brandWOFF2(2048)),
	}
}

// slots is a write's six slots naming kit's assets.
func (kit kitUploads) slots() map[string]any {
	return map[string]any{
		"logo": map[string]any{"id": kit.logo.Id}, "darkLogo": map[string]any{"id": kit.darkLogo.Id},
		"favicon": map[string]any{"id": kit.favicon.Id}, "background": map[string]any{"id": kit.background.Id},
		"regularFont": map[string]any{"id": kit.regularFont.Id}, "boldFont": map[string]any{"id": kit.boldFont.Id},
	}
}

// assetAsAnswered is an uploaded asset as a brand's slot answers it, decoded from JSON.
func assetAsAnswered(asset brandAssetAnswer) map[string]any {
	return map[string]any{"id": float64(asset.Id), "kind": asset.Kind, "url": asset.Url,
		"contentType": asset.ContentType, "width": float64(asset.Width), "height": float64(asset.Height)}
}

func TestAPIBrands_SlotsNameUploadedAssetsAndReadBackUnchanged(t *testing.T) {
	accessToken, _ := createAdminClientWithToken(t)
	_, created := keepDefaultBrand(t)
	kit := uploadKit(t, accessToken)

	body := brandBody(map[string]any{"name": brandName("Kit"), "appearance": "auto", "theme": "plum",
		"font": "uploaded", "backgroundFit": "contain", "hideAppName": true})
	for slot, ref := range kit.slots() {
		body[slot] = ref
	}
	status, answer, _ := brandCall(t, accessToken, http.MethodPost, brandsPath, body)
	require.Equal(t, http.StatusCreated, status, "%v", answer)
	brand := answer["brand"].(map[string]any)
	id := int64(brand["id"].(float64))
	*created = append(*created, id)
	for slot, asset := range map[string]brandAssetAnswer{"logo": kit.logo, "darkLogo": kit.darkLogo, "favicon": kit.favicon,
		"background": kit.background, "regularFont": kit.regularFont, "boldFont": kit.boldFont} {
		assert.Equal(t, assetAsAnswered(asset), brand[slot], slot)
	}

	// Stored on the brand's slots, the engine's foreign keys naming the uploaded assets.
	stored, err := database.GetBrandById(context.Background(), nil, id)
	require.NoError(t, err)
	assert.Equal(t, []int64{kit.logo.Id, kit.darkLogo.Id, kit.favicon.Id, kit.background.Id, kit.regularFont.Id, kit.boldFont.Id},
		[]int64{stored.LogoAssetId.Int64, stored.DarkLogoAssetId.Int64, stored.FaviconAssetId.Int64,
			stored.BackgroundAssetId.Int64, stored.RegularFontAssetId.Int64, stored.BoldFontAssetId.Int64})

	// A brand read and sent back as its own update is unchanged.
	status, read, _ := brandCall(t, accessToken, http.MethodGet, brandPath(id, ""), nil)
	require.Equal(t, http.StatusOK, status)
	assertBrandReadsAsCreated(t, brand, read["brand"].(map[string]any))
	status, again, _ := brandCall(t, accessToken, http.MethodPut, brandPath(id, ""), read["brand"])
	require.Equal(t, http.StatusOK, status, "%v", again)
	rewritten, err := database.GetBrandById(context.Background(), nil, id)
	require.NoError(t, err)
	rewritten.UpdatedAt = stored.UpdatedAt
	assert.Equal(t, stored, rewritten)

	// An update is a full replace: the slots it leaves out are emptied, and the font goes back to a
	// system family, as the uploaded font needs its regular file.
	update := brandBody(map[string]any{"name": brandName("Kit"), "appearance": "auto", "theme": "plum",
		"logo": map[string]any{"id": kit.logo.Id}})
	status, answer, _ = brandCall(t, accessToken, http.MethodPut, brandPath(id, ""), update)
	require.Equal(t, http.StatusOK, status, "%v", answer)
	assert.Equal(t, assetAsAnswered(kit.logo), answer["brand"].(map[string]any)["logo"])
	for _, slot := range []string{"darkLogo", "favicon", "background", "regularFont", "boldFont"} {
		assert.Nil(t, answer["brand"].(map[string]any)[slot], slot)
	}
	emptied, err := database.GetBrandById(context.Background(), nil, id)
	require.NoError(t, err)
	assert.True(t, emptied.LogoAssetId.Valid)
	assert.False(t, emptied.DarkLogoAssetId.Valid)
	assert.False(t, emptied.FaviconAssetId.Valid)
	assert.False(t, emptied.BackgroundAssetId.Valid)
	assert.False(t, emptied.RegularFontAssetId.Valid)
	assert.False(t, emptied.BoldFontAssetId.Valid)
}

func TestAPIBrands_SlotRefusals(t *testing.T) {
	accessToken, _ := createAdminClientWithToken(t)
	_, created := keepDefaultBrand(t)
	other := createBrandOverAPI(t, accessToken, created, brandName("Other"), "auto", "blueberry")
	kit := uploadKit(t, accessToken)
	ref := func(asset brandAssetAnswer) map[string]any { return map[string]any{"id": asset.Id} }

	refusals := []struct {
		name  string
		slots map[string]any
		code  string
		text  string
	}{
		{"a logo naming a favicon", map[string]any{"logo": ref(kit.favicon)},
			"handler.brand.logo_asset_invalid", "The logo is not a stored logo. Upload it again."},
		{"a logo naming no asset", map[string]any{"logo": map[string]any{"id": 999999999}},
			"handler.brand.logo_asset_invalid", "The logo is not a stored logo. Upload it again."},
		{"a dark logo naming a background", map[string]any{"logo": ref(kit.logo), "darkLogo": ref(kit.background)},
			"handler.brand.dark_logo_asset_invalid", "The dark logo is not a stored logo. Upload it again."},
		{"a favicon naming a logo", map[string]any{"favicon": ref(kit.logo)},
			"handler.brand.favicon_asset_invalid", "The favicon is not a stored favicon. Upload it again."},
		{"a background naming a font", map[string]any{"background": ref(kit.regularFont)},
			"handler.brand.background_asset_invalid", "The background image is not a stored background image. Upload it again."},
		{"a regular font naming a logo", map[string]any{"regularFont": ref(kit.logo)},
			"handler.brand.regular_font_asset_invalid", "The regular font file is not a stored font. Upload it again."},
		{"a bold font naming a favicon", map[string]any{"regularFont": ref(kit.regularFont), "boldFont": ref(kit.favicon)},
			"handler.brand.bold_font_asset_invalid", "The bold font file is not a stored font. Upload it again."},
		{"a dark logo without a logo", map[string]any{"darkLogo": ref(kit.darkLogo)},
			"handler.brand.dark_logo_logo_required", "Upload a logo to use a dark logo."},
		{"a bold font without a regular one", map[string]any{"boldFont": ref(kit.boldFont)},
			"handler.brand.bold_font_regular_required", "Upload a regular font file to use a bold one."},
		{"the uploaded font with a bold file alone", map[string]any{"font": "uploaded", "boldFont": ref(kit.boldFont)},
			"handler.brand.uploaded_font_regular_required", "Upload a regular font file to use the uploaded font."},
	}
	for _, c := range refusals {
		body := func() map[string]any {
			body := brandBody(map[string]any{"name": brandName("New"), "appearance": "auto", "theme": "avocado"})
			for key, value := range c.slots {
				body[key] = value
			}
			return body
		}
		t.Run("create: "+c.name, func(t *testing.T) {
			status, answer, _ := brandCall(t, accessToken, http.MethodPost, brandsPath, body())
			assert.Equal(t, http.StatusBadRequest, status)
			assert.Equal(t, c.code, answer["error_code"])
			assert.Equal(t, c.text, answer["error_description"])
		})
		t.Run("update: "+c.name, func(t *testing.T) {
			status, answer, _ := brandCall(t, accessToken, http.MethodPut, brandPath(other, ""), body())
			assert.Equal(t, http.StatusBadRequest, status)
			assert.Equal(t, c.code, answer["error_code"])
		})
	}
	unchanged, err := database.GetBrandById(context.Background(), nil, other)
	require.NoError(t, err)
	assert.False(t, unchanged.LogoAssetId.Valid, "no refused update wrote a slot")
}

// kitCard is what a page draws of its brand's kit: the card's logo images, their src and alt, the
// dark-mode sources, whether the name is shown, and the icon links in the head.
type kitCard struct {
	images, alts, darkSources, iconHrefs, touchHrefs []string
	names, manifests                                 int
}

func readKitCard(t *testing.T, resp *http.Response) kitCard {
	t.Helper()
	doc := parseHTMLResponse(t, resp)
	var card kitCard
	doc.Find(".auth-card .auth-logo img").Each(func(_ int, img *goquery.Selection) {
		src, _ := img.Attr("src")
		alt, hasAlt := img.Attr("alt")
		require.True(t, hasAlt, "every image carries an alt attribute")
		card.images = append(card.images, src)
		card.alts = append(card.alts, alt)
	})
	doc.Find(".auth-card .auth-logo source").Each(func(_ int, source *goquery.Selection) {
		srcset, _ := source.Attr("srcset")
		card.darkSources = append(card.darkSources, srcset)
	})
	doc.Find(`head link[rel="icon"]`).Each(func(_ int, link *goquery.Selection) {
		href, _ := link.Attr("href")
		card.iconHrefs = append(card.iconHrefs, href)
	})
	doc.Find(`head link[rel="apple-touch-icon"]`).Each(func(_ int, link *goquery.Selection) {
		href, _ := link.Attr("href")
		card.touchHrefs = append(card.touchHrefs, href)
	})
	card.names = doc.Find(".auth-card p.auth-brand").Length()
	card.manifests = doc.Find(`head link[rel="manifest"]`).Length()
	return card
}

func TestPages_TheKitIsDrawnOnTheCardInTheHeadAndInTheStylesheet(t *testing.T) {
	accessToken, _ := createAdminClientWithToken(t)
	_, created := keepDefaultBrand(t)
	kit := uploadKit(t, accessToken)
	body := brandBody(map[string]any{"name": brandName("Pages"), "appearance": "auto", "theme": "plum",
		"font": "uploaded", "backgroundFit": "tile", "hideAppName": true})
	for slot, ref := range kit.slots() {
		body[slot] = ref
	}
	status, answer, _ := brandCall(t, accessToken, http.MethodPost, brandsPath, body)
	require.Equal(t, http.StatusCreated, status, "%v", answer)
	id := int64(answer["brand"].(map[string]any)["id"].(float64))
	*created = append(*created, id)
	status, answer, _ = brandCall(t, accessToken, http.MethodPost, brandPath(id, "/make-default"), nil)
	require.Equal(t, http.StatusOK, status, "%v", answer)

	base := appConfig.AuthServer.BaseURL
	path := func(asset brandAssetAnswer) string { return strings.TrimPrefix(asset.Url, base) }
	client := newFormPostClient(t)

	for _, tc := range []struct {
		name string
		load func(t *testing.T, browser *http.Client) *http.Response
	}{
		{"the not-found page", func(t *testing.T, browser *http.Client) *http.Response {
			return loadPage(t, browser, base+"/no-such-page-kit")
		}},
		{"the password page", func(t *testing.T, browser *http.Client) *http.Response {
			params := formPostAuthorizeParams(client, "code", "", formPostHTTPSURI, "")
			resp := loadPage(t, browser, base+"/auth/authorize?"+params.Encode())
			location := assertRedirect(t, resp, "/auth/level1")
			_ = resp.Body.Close()
			resp = loadPage(t, browser, location)
			location = assertRedirect(t, resp, "/auth/pwd")
			_ = resp.Body.Close()
			return loadPage(t, browser, location)
		}},
		{"the form_post page", func(t *testing.T, browser *http.Client) *http.Response {
			params := formPostAuthorizeParams(client, "code", "form_post", formPostHTTPSURI, "none")
			return loadPage(t, browser, base+"/auth/authorize?"+params.Encode())
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			browser := createHttpClient(t)
			resp := tc.load(t, browser)
			defer func() { _ = resp.Body.Close() }()

			card := readKitCard(t, resp)
			// An automatic brand: the light logo, with the dark one as its source in dark mode, and
			// the app name as its alt while the name's text is hidden.
			assert.Equal(t, []string{path(kit.logo)}, card.images)
			assert.Equal(t, []string{path(kit.darkLogo)}, card.darkSources)
			assert.NotEmpty(t, card.alts[0])
			assert.Zero(t, card.names, "the name's text gives way to the logo")
			assert.Equal(t, []string{path(kit.favicon)}, card.iconHrefs)
			assert.Equal(t, []string{path(kit.favicon)}, card.touchHrefs)
			assert.Zero(t, card.manifests)
		})
	}

	// The logo the card links is served, as current, to anyone.
	browser := createHttpClient(t)
	status, _, header := getStylesheet(t, browser, kit.logo.Url)
	assert.Equal(t, http.StatusOK, status)
	assert.Equal(t, "public, max-age=31536000, immutable", header.Get("Cache-Control"))

	// The public settings carry the images and the switch, and the full stylesheet's URL.
	status, settings, _ := getStylesheet(t, browser, base+"/api/public/settings")
	require.Equal(t, http.StatusOK, status)
	var published struct {
		Brand struct {
			StylesheetURL string `json:"stylesheetUrl"`
			LogoURL       string `json:"logoUrl"`
			DarkLogoURL   string `json:"darkLogoUrl"`
			FaviconURL    string `json:"faviconUrl"`
			HideAppName   bool   `json:"hideAppName"`
		} `json:"brand"`
	}
	require.NoError(t, json.Unmarshal([]byte(settings), &published))
	assert.Equal(t, kit.logo.Url, published.Brand.LogoURL)
	assert.Equal(t, kit.darkLogo.Url, published.Brand.DarkLogoURL)
	assert.Equal(t, kit.favicon.Url, published.Brand.FaviconURL)
	assert.True(t, published.Brand.HideAppName)

	// The full stylesheet draws the background at its fit and the uploaded font from both files, by
	// the paths the assets are served at.
	status, full, _ := getStylesheet(t, browser, published.Brand.StylesheetURL)
	require.Equal(t, http.StatusOK, status)
	assert.Contains(t, full, ".auth-page {\n  background-image: url(\""+path(kit.background)+"\");\n  background-repeat: repeat;\n}\n")
	assert.Contains(t, full, "  src: url(\""+path(kit.regularFont)+"\") format(\"woff2\");\n  font-weight: 1 500;\n")
	assert.Contains(t, full, "  src: url(\""+path(kit.boldFont)+"\") format(\"woff2\");\n  font-weight: 501 1000;\n")
	assert.Contains(t, full, "  --font-sans: \"brand-font\", -apple-system,")
	assert.NotContains(t, full, path(kit.logo), "the page draws the logo, not the stylesheet")
}
