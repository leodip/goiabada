package integration

import (
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/fake"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A sign-out's pages are drawn in the brand of the client the request names: by a valid
// id_token_hint, or with no hint by client_id. That covers the page asking whether to sign out, the
// signed-out page after it is confirmed, and the declined page its declining link leads to. A
// sign-out whose hint was rejected, and one whose client_id names no client, is drawn in the default
// brand on every page (#812 decision 5).
//
// Each test makes a dark Plum brand the default and gives the client a light Avocado brand, so a
// page drawn in the wrong one fails on its data-theme, its color-scheme and its stylesheet alike.

// signOutDeclinedPage loads the page asking whether to sign out for query, in a browser of its own,
// follows its declining link as a browser without script would, and answers the declined page and
// the link's query.
func signOutDeclinedPage(t *testing.T, query url.Values) (*http.Response, url.Values) {
	t.Helper()
	browser := createHttpClient(t)

	consent := loadPage(t, browser, appConfig.AuthServer.BaseURL+"/auth/logout?"+query.Encode())
	require.Equal(t, http.StatusOK, consent.StatusCode)
	doc := parseHTMLResponse(t, consent)
	_ = consent.Body.Close()

	href, ok := doc.Find("form a").Attr("href")
	require.True(t, ok, "the page asking whether to sign out has a declining link")
	base, err := url.Parse(appConfig.AuthServer.BaseURL + "/auth/logout")
	require.NoError(t, err)
	destination, err := base.Parse(href)
	require.NoError(t, err)
	require.Equal(t, "/auth/logout/declined", destination.Path)

	return loadPage(t, browser, destination.String()), destination.Query()
}

// assertSignOutPagesDrawnIn drives the three pages of a sign-out asked for by query, each in a browser
// of its own, and asserts each is drawn in brand.
func assertSignOutPagesDrawnIn(t *testing.T, query url.Values, brand *record.Brand, dataTheme string) {
	t.Helper()

	t.Run("the page asking whether to sign out", func(t *testing.T) {
		page := loadPage(t, createHttpClient(t), appConfig.AuthServer.BaseURL+"/auth/logout?"+query.Encode())
		defer func() { _ = page.Body.Close() }()
		require.Equal(t, http.StatusOK, page.StatusCode)
		assertDrawnInBrand(t, page, brand, dataTheme)
	})

	t.Run("the declined page", func(t *testing.T) {
		page, _ := signOutDeclinedPage(t, query)
		defer func() { _ = page.Body.Close() }()
		require.Equal(t, http.StatusOK, page.StatusCode)
		assertDrawnInBrand(t, page, brand, dataTheme)
	})

	t.Run("the signed-out page after it is confirmed", func(t *testing.T) {
		page := logoutThroughConsentPage(t, createHttpClient(t), query)
		defer func() { _ = page.Body.Close() }()
		require.Equal(t, http.StatusOK, page.StatusCode)
		assertDrawnInBrand(t, page, brand, dataTheme)
	})
}

func TestSignOutPages_ASignOutNamingItsClientByClientIdIsDrawnInTheClientsBrand(t *testing.T) {
	makeDefaultBrand(t, record.BrandAppearanceDark, "plum")
	client, _ := brandSignInClient(t, record.AcrLevel1)
	clientBrand := giveClientBrand(t, client, record.BrandAppearanceLight, "avocado")

	assertSignOutPagesDrawnIn(t, url.Values{"client_id": {client.ClientIdentifier}}, clientBrand, "light")
}

// The declining link carries client_id beside ui_locales, for the brand alone, and nothing else of
// the request: a decline is not a sign-out and hands the app nothing.
func TestSignOutPages_TheDecliningLinkCarriesTheClientForItsBrand(t *testing.T) {
	makeDefaultBrand(t, record.BrandAppearanceDark, "plum")
	client, _ := brandSignInClient(t, record.AcrLevel1)
	giveClientBrand(t, client, record.BrandAppearanceLight, "avocado")

	page, query := signOutDeclinedPage(t, url.Values{
		"client_id":                {client.ClientIdentifier},
		"ui_locales":               {"pt-BR"},
		"state":                    {"s"},
		"post_logout_redirect_uri": {"https://brand.example.com/signed-out"},
	})
	_ = page.Body.Close()
	assert.Equal(t, url.Values{"client_id": {client.ClientIdentifier}, "ui_locales": {"pt-BR"}}, query)
}

func TestSignOutPages_ASignOutWithAValidHintIsDrawnInTheClientsBrand(t *testing.T) {
	makeDefaultBrand(t, record.BrandAppearanceDark, "plum")
	grant := createOfflineGrant(t)
	clientBrand := giveClientBrand(t, grant.client, record.BrandAppearanceLight, "avocado")
	idToken, _ := sessionBoundGrantOnSameSession(t, grant)

	// A valid hint skips the question, so its one page is the signed-out page.
	page := loadPage(t, grant.httpClient, appConfig.AuthServer.BaseURL+"/auth/logout?"+
		url.Values{"id_token_hint": {idToken}}.Encode())
	defer func() { _ = page.Body.Close() }()
	require.Equal(t, http.StatusOK, page.StatusCode)
	body := bodyString(t, page)
	page.Body = io.NopCloser(strings.NewReader(body))
	assertSignedOutPage(t, page, signedOutEnglish, false)
	page.Body = io.NopCloser(strings.NewReader(body))
	assertDrawnInBrand(t, page, clientBrand, "light")
}

// A rejected hint is drawn in the default on every page, also when the client_id beside it names a
// client with a brand of its own; and so is a client_id that names no client, and one that names a
// client with no brand of its own.
func TestSignOutPages_StayInTheDefaultBrandWhenNoClientIsNamed(t *testing.T) {
	defaultBrand := makeDefaultBrand(t, record.BrandAppearanceDark, "plum")
	branded, _ := brandSignInClient(t, record.AcrLevel1)
	giveClientBrand(t, branded, record.BrandAppearanceLight, "avocado")
	plain, _ := brandSignInClient(t, record.AcrLevel1)

	for _, tc := range []struct {
		name  string
		query url.Values
	}{
		{"a rejected hint beside a branded client's client_id", url.Values{
			"id_token_hint": {"not.a.token"},
			"client_id":     {branded.ClientIdentifier},
		}},
		{"a client_id that names no client", url.Values{"client_id": {"no-such-client-" + fake.LetterN(8)}}},
		{"a client with no brand of its own", url.Values{"client_id": {plain.ClientIdentifier}}},
		{"no client_id", url.Values{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assertSignOutPagesDrawnIn(t, tc.query, defaultBrand, "dark")
		})
	}

	t.Run("the declining link of a rejected hint carries no client", func(t *testing.T) {
		page, query := signOutDeclinedPage(t, url.Values{
			"id_token_hint": {"not.a.token"},
			"client_id":     {branded.ClientIdentifier},
		})
		_ = page.Body.Close()
		assert.Empty(t, query)
	})
}
