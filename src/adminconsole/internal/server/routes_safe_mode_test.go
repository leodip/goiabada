package server

import (
	"html"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The brand the auth server publishes, with its safe links beside its own.
const safeModeBrand = `{"appearance":"auto",` +
	`"stylesheetUrl":"https://id.example.test/brand/7/stylesheet.css?v=1",` +
	`"colorsStylesheetUrl":"https://id.example.test/brand/7/colors.css?v=2",` +
	`"safeStylesheetUrl":"https://id.example.test/brand/7/safe-stylesheet.css?v=3",` +
	`"safeColorsStylesheetUrl":"https://id.example.test/brand/7/safe-colors.css?v=4",` +
	`"safeMode":false}`

func turnstileSettingsAPI(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/api/v1/admin/settings/turnstile" {
		http.NotFound(w, r)
		return
	}
	_, _ = w.Write([]byte(`{"turnstileEnabled":false,"turnstileSiteKey":"","hasTurnstileSecretKey":false}`))
}

// goiabada_safe_mode=true on a console URL puts the signed-in browser's console session in safe
// mode: that page and every later one, admin and Account alike, is drawn from the safe links, and the
// admin pages say so. Another browser's session is not (#816 decision 2).
func TestInitRoutes_SafeModeOnAConsoleURLLastsForTheSession(t *testing.T) {
	const scope = "openid authserver:manage authserver:manage-account"
	s, cookies := newSignedInConsoleWithBrand(t, scope, safeModeBrand, turnstileSettingsAPI)

	first := serveRouting(s, http.MethodGet, "/admin/settings/turnstile?goiabada_safe_mode=true", nil, cookies...)
	require.Equal(t, http.StatusOK, first.Code, first.Body.String())
	assert.Contains(t, first.Body.String(), `<link rel="stylesheet" href="https://id.example.test/brand/7/safe-colors.css?v=4">`)
	assert.Contains(t, first.Body.String(), "Sign out to leave safe mode.")

	later := serveRouting(s, http.MethodGet, "/admin/settings/turnstile", nil, cookies...)
	require.Equal(t, http.StatusOK, later.Code, later.Body.String())
	assert.Contains(t, later.Body.String(), `<link rel="stylesheet" href="https://id.example.test/brand/7/safe-colors.css?v=4">`)
	assert.NotContains(t, later.Body.String(), "brand/7/colors.css")
	assert.Contains(t, later.Body.String(), "Sign out to leave safe mode.")

	account := serveRouting(s, http.MethodGet, "/account/data", nil, cookies...)
	require.Equal(t, http.StatusOK, account.Code, account.Body.String())
	assert.Contains(t, account.Body.String(), `<link rel="stylesheet" href="https://id.example.test/brand/7/safe-stylesheet.css?v=3">`)
	assert.NotContains(t, account.Body.String(), "Sign out to leave safe mode.", "the notice is on admin pages alone")

	other, otherCookies := newSignedInConsoleWithBrand(t, scope, safeModeBrand, turnstileSettingsAPI)
	page := serveRouting(other, http.MethodGet, "/admin/settings/turnstile", nil, otherCookies...)
	require.Equal(t, http.StatusOK, page.Code, page.Body.String())
	assert.Contains(t, page.Body.String(), `<link rel="stylesheet" href="https://id.example.test/brand/7/colors.css?v=2">`)
	assert.NotContains(t, page.Body.String(), "safe mode")
}

// A browser that is not signed in is sent to sign in with goiabada_safe_mode=true on the
// authorization request, from an admin URL and an Account URL alike, and only when its console URL
// asked for it.
func TestInitRoutes_ASignInFromASafeConsoleURLAsksForSafeMode(t *testing.T) {
	s, authServerURL := newRoutingTestServer(t)

	for _, target := range []string{"/admin/clients?goiabada_safe_mode=true", "/account/profile?goiabada_safe_mode=true"} {
		rec := serveRouting(s, http.MethodGet, target, nil)
		require.Equal(t, http.StatusFound, rec.Code, target)
		location := rec.Header().Get("Location")
		require.True(t, strings.HasPrefix(location, authServerURL+"/auth/authorize?"), location)
		query, err := url.ParseQuery(strings.TrimPrefix(location, authServerURL+"/auth/authorize?"))
		require.NoError(t, err)
		assert.Equal(t, []string{"true"}, query["goiabada_safe_mode"], target)
	}

	rec := serveRouting(s, http.MethodGet, "/admin/clients", nil)
	require.Equal(t, http.StatusFound, rec.Code)
	assert.NotContains(t, rec.Header().Get("Location"), "goiabada_safe_mode")
}

// The home page is drawn for a browser not signed in, and nothing keeps its safe mode past that
// request (#620): so a home page opened with goiabada_safe_mode=true carries it on its two sign-in
// links, Your account and Administration, and following either starts a sign-in that asks for safe
// mode. Opened without it, the links are bare (#816 decision 2).
func TestInitRoutes_ASafeHomePagesLinksStartSafeSignIns(t *testing.T) {
	s, authServerURL := newRoutingTestServer(t)

	hrefs := func(target string) map[string]string {
		home := serveRouting(s, http.MethodGet, target, nil)
		require.Equal(t, http.StatusOK, home.Code, home.Body.String())
		found := map[string]string{}
		for _, match := range regexp.MustCompile(`href="([^"]*)"`).FindAllStringSubmatch(home.Body.String(), -1) {
			href := html.UnescapeString(match[1])
			parsed, err := url.Parse(href)
			require.NoError(t, err)
			if parsed.Path == "/admin/clients" || parsed.Path == "/account/profile" {
				found[parsed.Path] = href
			}
		}
		return found
	}

	safe := hrefs("/?goiabada_safe_mode=true")
	assert.Equal(t, map[string]string{
		"/account/profile": "/account/profile?goiabada_safe_mode=true",
		"/admin/clients":   "/admin/clients?goiabada_safe_mode=true",
	}, safe)
	for path, href := range safe {
		signIn := serveRouting(s, http.MethodGet, href, nil)
		require.Equal(t, http.StatusFound, signIn.Code, path)
		location := signIn.Header().Get("Location")
		require.True(t, strings.HasPrefix(location, authServerURL+"/auth/authorize?"), location)
		query, err := url.ParseQuery(strings.TrimPrefix(location, authServerURL+"/auth/authorize?"))
		require.NoError(t, err)
		assert.Equal(t, []string{"true"}, query["goiabada_safe_mode"], path)
	}

	for _, target := range []string{"/", "/?goiabada_safe_mode=false"} {
		assert.Equal(t, map[string]string{
			"/account/profile": "/account/profile",
			"/admin/clients":   "/admin/clients",
		}, hrefs(target), target)
	}
}
