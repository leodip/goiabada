package integration

import (
	"context"
	"database/sql"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/fake"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// goiabada_safe_mode=true on an authorization request draws that sign-in in safe mode (#816
// decisions 1 and 3): every page of it links its client's brand by the brand's safe stylesheet, which
// leaves out the custom CSS and draws Blueberry in place of the custom palette. The pages a sign-in
// links to follow while their URL names it, and no other sign-in is drawn safe, the next one in the
// same browser included. Nothing stored changes.

// safeModeCSS is custom CSS whose rule a page drawn safe never receives.
const safeModeCSS = ".auth-card { border: 7px dashed var(--color-brand); }"

// safeModeLight is a custom palette mode with every token set to one gray.
func safeModeLight() map[string]string {
	colors := map[string]string{}
	for _, token := range []string{"canvas", "surface", "subtle", "line", "line-strong", "ink", "ink-muted",
		"brand", "brand-strong", "on-brand", "brand-soft", "danger", "danger-strong", "on-danger", "danger-soft",
		"danger-ink", "positive-soft", "positive-ink", "caution-soft", "caution-ink", "note-soft", "note-ink", "focus"} {
		colors[token] = "#777777"
	}
	return colors
}

// giveClientSafeModeBrand creates a light brand on a custom palette with custom CSS and gives it to
// client. The brand is deleted when the test ends, which puts the client back on the default.
func giveClientSafeModeBrand(t *testing.T, client *record.Client) *record.Brand {
	t.Helper()
	ctx := context.Background()
	brand := record.NewBrand("Safe "+fake.LetterN(10), record.BrandAppearanceLight, record.BrandThemeCustom)
	brand.Palette = &record.BrandPalette{Mode: record.BrandPaletteModeAdvanced, Light: safeModeLight(), Dark: safeModeLight()}
	brand.CustomCSS = safeModeCSS
	require.NoError(t, database.CreateBrand(ctx, nil, &brand))
	t.Cleanup(func() {
		assert.NoError(t, database.RunInTransaction(ctx, func(tx *sql.Tx) error {
			_, err := database.DeleteBrand(ctx, tx, brand.Id)
			return err
		}), "unable to delete the client's brand")
	})
	require.NoError(t, database.RunInTransaction(ctx, func(tx *sql.Tx) error {
		_, err := database.SetClientBrand(ctx, tx, client.Id, sql.NullInt64{Int64: brand.Id, Valid: true})
		return err
	}))
	return &brand
}

// brandStylesheetLink answers the brand stylesheet a page links after main.css.
func brandStylesheetLink(t *testing.T, resp *http.Response) string {
	t.Helper()
	head := readBrandedPageHead(t, resp)
	require.Len(t, head.stylesheets, 2, "main.css, then the brand's stylesheet")
	return head.stylesheets[1]
}

// assertDrawnSafe asserts a page links brand's safe stylesheet, in the brand's light appearance.
func assertDrawnSafe(t *testing.T, resp *http.Response, brand *record.Brand) {
	t.Helper()
	head := readBrandedPageHead(t, resp)
	assert.Equal(t, "light", head.dataTheme, "the appearance stays")
	if assert.Len(t, head.stylesheets, 2, "main.css, then the brand's stylesheet") {
		assert.Regexp(t, `^/brand/`+strconv.FormatInt(brand.Id, 10)+`/safe-stylesheet\.css\?v=[0-9a-f]{12}$`,
			head.stylesheets[1])
	}
}

// withSafeMode is an authorization request's URL with goiabada_safe_mode=true.
func withSafeMode(t *testing.T, raw string) string {
	t.Helper()
	parsed, err := url.Parse(raw)
	require.NoError(t, err)
	params := parsed.Query()
	params.Set("goiabada_safe_mode", "true")
	parsed.RawQuery = params.Encode()
	return parsed.String()
}

// getBody answers the body served at path on the auth server.
func getBody(t *testing.T, path string) string {
	t.Helper()
	resp, err := createHttpClient(t).Get(appConfig.AuthServer.BaseURL + path)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusOK, resp.StatusCode, path)
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	return string(body)
}

func TestSafeMode_ASignInAskingForItIsDrawnSafeOnEveryPage(t *testing.T) {
	useMailpitSMTP(t)
	makeDefaultBrand(t, record.BrandAppearanceDark, "plum")
	client, redirectURI := brandSignInClient(t, record.AcrLevel1)
	brand := giveClientSafeModeBrand(t, client)
	user, password := brandSignInUser(t, "")
	browser := createHttpClient(t)

	resp := loadPage(t, browser, withSafeMode(t, brandAuthorizeURL(client, redirectURI, "form_post")))
	resp, _ = brandFollowTo(t, browser, resp, "/auth/level1")
	pwdPage, pwdURL := brandFollowTo(t, browser, resp, "/auth/pwd")
	t.Run("the password page", func(t *testing.T) {
		require.Equal(t, http.StatusOK, pwdPage.StatusCode)
		assertDrawnSafe(t, pwdPage, brand)
	})

	// The safe stylesheet the pages link holds neither the CSS nor the palette.
	t.Run("the safe stylesheet", func(t *testing.T) {
		safe := getBody(t, brandStylesheetLink(t, pwdPage))
		assert.NotContains(t, safe, "7px dashed")
		assert.NotContains(t, safe, "#777777")
		assert.Equal(t, "/* Blueberry is the palette main.css is built with: this stylesheet declares no colors. */\n", safe)
	})

	// The page a sign-in links to follows it while its URL names it.
	t.Run("the forgot password page it links to", func(t *testing.T) {
		page := parseHTMLResponse(t, pwdPage)
		href, ok := page.Find(`a[href^="/forgot-password"]`).Attr("href")
		require.True(t, ok, "the password page links Forgot password?")
		forgot := loadPage(t, browser, appConfig.AuthServer.BaseURL+href)
		defer func() { _ = forgot.Body.Close() }()
		require.Equal(t, http.StatusOK, forgot.StatusCode)
		assertDrawnSafe(t, forgot, brand)
	})

	refused := authenticateWithPassword(t, browser, pwdURL, pwdPage, user.Email, "not-"+password)
	_ = pwdPage.Body.Close()
	t.Run("the password page refusing a wrong password", func(t *testing.T) {
		require.Equal(t, http.StatusOK, refused.StatusCode)
		assertDrawnSafe(t, refused, brand)
	})

	resp = authenticateWithPassword(t, browser, pwdURL, refused, user.Email, password)
	_ = refused.Body.Close()
	resp, _ = brandFollowTo(t, browser, resp, "/auth/level1completed")
	resp, _ = brandFollowTo(t, browser, resp, "/auth/completed")
	consentPage, consentURL := brandFollowTo(t, browser, resp, "/auth/consent")
	defer func() { _ = consentPage.Body.Close() }()
	t.Run("the consent page", func(t *testing.T) {
		require.Equal(t, http.StatusOK, consentPage.StatusCode)
		assertDrawnSafe(t, consentPage, brand)
	})

	resp = postConsent(t, browser, consentURL, consentPage, consentIndices(t, consentPage))
	formPost, _ := brandFollowTo(t, browser, resp, "/auth/issue")
	defer func() { _ = formPost.Body.Close() }()
	t.Run("the form_post page delivering the code", func(t *testing.T) {
		require.Equal(t, http.StatusOK, formPost.StatusCode)
		assertDrawnSafe(t, formPost, brand)
	})

	// The next sign-in in the same browser did not ask for it, and is drawn as usual.
	t.Run("the next sign-in in the same browser", func(t *testing.T) {
		page := followToPage(t, browser, brandAuthorizeURL(client, redirectURI, "form_post"))
		defer func() { _ = page.Body.Close() }()
		require.Equal(t, http.StatusOK, page.StatusCode)
		assert.Regexp(t, `^/brand/`+strconv.FormatInt(brand.Id, 10)+`/stylesheet\.css\?v=[0-9a-f]{12}$`,
			brandStylesheetLink(t, page))
	})

	// Another browser's sign-in, of the same client, is drawn as usual.
	t.Run("another browser's sign-in", func(t *testing.T) {
		other := createHttpClient(t)
		page := loadPage(t, other, brandAuthorizeURL(client, redirectURI, ""))
		page, _ = brandFollowTo(t, other, page, "/auth/level1")
		page, _ = brandFollowTo(t, other, page, "/auth/pwd")
		defer func() { _ = page.Body.Close() }()
		require.Equal(t, http.StatusOK, page.StatusCode)
		assert.Regexp(t, `^/brand/`+strconv.FormatInt(brand.Id, 10)+`/stylesheet\.css\?v=[0-9a-f]{12}$`,
			brandStylesheetLink(t, page))
	})

	// Nothing stored changes.
	t.Run("the stored brand", func(t *testing.T) {
		stored, err := database.GetBrandById(context.Background(), nil, brand.Id)
		require.NoError(t, err)
		require.NotNil(t, stored)
		assert.Equal(t, safeModeCSS, stored.CustomCSS)
		assert.Equal(t, record.BrandThemeCustom, stored.Theme)
		require.NotNil(t, stored.Palette)
		assert.Equal(t, safeModeLight(), stored.Palette.Light)
	})
}

// A refusal page the authorization endpoint draws once the client is known is drawn safe when the
// request asks for it, from the first page.
func TestSafeMode_TheAuthorizeRefusalPageIsDrawnSafe(t *testing.T) {
	makeDefaultBrand(t, record.BrandAppearanceDark, "plum")
	client, redirectURI := brandSignInClient(t, record.AcrLevel1)
	brand := giveClientSafeModeBrand(t, client)

	resp := loadPage(t, createHttpClient(t),
		withSafeMode(t, brandAuthorizeURL(client, "https://elsewhere.example.com/callback", "")))
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	assertDrawnSafe(t, resp, brand)

	asUsual := loadPage(t, createHttpClient(t), brandAuthorizeURL(client, redirectURI, "no-such-mode"))
	defer func() { _ = asUsual.Body.Close() }()
	require.Equal(t, http.StatusBadRequest, asUsual.StatusCode)
	assert.Regexp(t, `/stylesheet\.css\?v=`, brandStylesheetLink(t, asUsual))
}

// The public settings carry the console client's brand's safe stylesheets beside its own, and say
// the operator's switch is off, as it is in this tier.
func TestSafeMode_ThePublicSettingsCarryTheSafeStylesheets(t *testing.T) {
	brand := record.NewBrand("Safe "+fake.LetterN(10), record.BrandAppearanceLight, record.BrandThemeCustom)
	brand.Palette = &record.BrandPalette{Mode: record.BrandPaletteModeAdvanced, Light: safeModeLight(), Dark: safeModeLight()}
	brand.CustomCSS = safeModeCSS
	makeDefaultBrandOf(t, &brand)

	resp, err := createHttpClient(t).Get(appConfig.AuthServer.BaseURL + "/api/public/settings")
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var body struct {
		Brand struct {
			StylesheetURL           string `json:"stylesheetUrl"`
			SafeStylesheetURL       string `json:"safeStylesheetUrl"`
			SafeColorsStylesheetURL string `json:"safeColorsStylesheetUrl"`
			SafeMode                *bool  `json:"safeMode"`
		} `json:"brand"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	id := strconv.FormatInt(brand.Id, 10)
	base := appConfig.AuthServer.BaseURL
	assert.Regexp(t, `^`+base+`/brand/`+id+`/stylesheet\.css\?v=[0-9a-f]{12}$`, body.Brand.StylesheetURL)
	assert.Regexp(t, `^`+base+`/brand/`+id+`/safe-stylesheet\.css\?v=[0-9a-f]{12}$`, body.Brand.SafeStylesheetURL)
	assert.Regexp(t, `^`+base+`/brand/`+id+`/safe-colors\.css\?v=[0-9a-f]{12}$`, body.Brand.SafeColorsStylesheetURL)
	require.NotNil(t, body.Brand.SafeMode, "safeMode is always carried")
	assert.False(t, *body.Brand.SafeMode)

	safeColors := getBody(t, body.Brand.SafeColorsStylesheetURL[len(base):])
	assert.NotContains(t, safeColors, "#777777", "Blueberry takes the custom palette's place")
}
