package integration

import (
	"context"
	"net/http"
	"net/url"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/fake"
	"github.com/leodip/goiabada/authserver/internal/passwordhash"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/builtin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A public client has no secret, so nothing in an authorization request proves which app sent it:
// another app on the device can send the same client_id and receive the redirect. RFC 6749 section
// 10.2 and RFC 8252 section 8.6 say such a request SHOULD be processed "as if no previous request
// had been approved" unless the client's identity can be proven. So for a public client with
// Remember consent off, a user's stored consent never stands in for the consent screen: a sign-in
// owing a consent shows the screen every time, and prompt=none owing one is answered
// consent_required, "User consent is required for every request from this client", without the
// stored consent being read. A sign-in owing no consent, and a refresh while the consent exists, are
// as before; a confidential client is unchanged whatever its row holds (#711 decisions 1 to 4).

// rememberConsentDescription is the prompt=none refusal of a client whose stored consent may not
// answer for the user, as decision 3 words it.
const rememberConsentDescription = "User consent is required for every request from this client"

// newRememberConsentFixture is a user holding manage-account, a browser, and a client answering at
// manageAccountRedirectURI, so the crafted link's helpers drive it: public with Remember consent as
// remember, or confidential with remember as its row. The fixture's clientSecret is set only for a
// confidential client.
func newRememberConsentFixture(t *testing.T, isPublic, consentRequired, remember bool) *manageAccountConsentFixture {
	t.Helper()

	client := &record.Client{
		ClientIdentifier:         "remember-consent-client-" + fake.LetterN(8),
		Enabled:                  true,
		AuthorizationCodeEnabled: true,
		IsPublic:                 isPublic,
		ConsentRequired:          consentRequired,
		RememberConsent:          remember,
		DefaultAcrLevel:          record.AcrLevel1,
	}
	var clientSecret string
	if isPublic {
		pkceRequired := true
		client.PKCERequired = &pkceRequired
	} else {
		clientSecret = fake.LetterN(32)
		encrypted, err := dataCipher.Encrypt(clientSecret)
		require.NoError(t, err)
		client.ClientSecretEncrypted = encrypted
	}
	require.NoError(t, database.CreateClient(context.Background(), nil, client))
	t.Cleanup(func() { _ = database.DeleteClient(context.Background(), nil, client.Id) })
	require.NoError(t, database.CreateRedirectURI(context.Background(), nil,
		&record.RedirectURI{ClientId: client.Id, URI: manageAccountRedirectURI}))

	password := fake.Password(10)
	passwordHashed, err := passwordhash.Hash(password)
	require.NoError(t, err)
	user := &record.User{Subject: fake.UUID(), Enabled: true, Email: fake.Email(), PasswordHash: passwordHashed}
	require.NoError(t, database.CreateUser(context.Background(), nil, user))
	t.Cleanup(func() { _ = database.DeleteUser(context.Background(), nil, user.Id) })
	assignPermissionToUser(t, user.Id, authServerPermissionId(t, builtin.ManageAccountPermissionIdentifier))

	return &manageAccountConsentFixture{
		client: client, clientSecret: clientSecret, user: user, password: password, browser: createHttpClient(t),
	}
}

// signInToConsentScreen signs the user in at the fixture's browser, which holds no session, through
// destUrl, and answers the consent screen's URL and the rendered page.
func signInToConsentScreen(t *testing.T, f *manageAccountConsentFixture, destUrl string) (string, *http.Response) {
	t.Helper()

	resp, err := f.browser.Get(destUrl)
	require.NoError(t, err)
	defer func(r *http.Response) { _ = r.Body.Close() }(resp)
	location := assertRedirect(t, resp, "/auth/level1")
	resp = loadPage(t, f.browser, location)
	defer func(r *http.Response) { _ = r.Body.Close() }(resp)
	location = assertRedirect(t, resp, "/auth/pwd")
	resp = loadPage(t, f.browser, location)
	defer func(r *http.Response) { _ = r.Body.Close() }(resp)
	resp = authenticateWithPassword(t, f.browser, location, resp, f.user.Email, f.password)
	defer func(r *http.Response) { _ = r.Body.Close() }(resp)
	location = assertRedirect(t, resp, "/auth/level1completed")
	resp = loadPage(t, f.browser, location)
	defer func(r *http.Response) { _ = r.Body.Close() }(resp)
	location = assertRedirect(t, resp, "/auth/completed")
	resp = loadPage(t, f.browser, location)
	defer func(r *http.Response) { _ = r.Body.Close() }(resp)
	location = assertRedirect(t, resp, "/auth/consent")
	page := loadPage(t, f.browser, location)
	require.Equal(t, http.StatusOK, page.StatusCode, "the consent screen is rendered")
	return location, page
}

// approve ticks every box of the consent screen and follows the answer to /auth/issue, which it
// answers.
func approve(t *testing.T, f *manageAccountConsentFixture, consentURL string, page *http.Response) *http.Response {
	t.Helper()

	ticked := make([]int, len(scopesOnScreen(t, page)))
	for i := range ticked {
		ticked[i] = i
	}
	resp := postConsent(t, f.browser, consentURL, page, ticked)
	defer func() { _ = resp.Body.Close() }()
	location := assertRedirect(t, resp, "/auth/issue")
	return loadPage(t, f.browser, location)
}

// redeemPublic exchanges the code /auth/issue answered for tokens, as a public client does: with its
// client_id and the PKCE verifier, and no secret.
func redeemPublic(t *testing.T, f *manageAccountConsentFixture, issueResponse *http.Response) (map[string]interface{}, *record.Code) {
	t.Helper()

	codeVal, state := getCodeAndStateFromUrl(t, issueResponse)
	assert.Equal(t, manageAccountState, state)
	code := loadCodeFromDatabase(t, codeVal)
	data := postToTokenEndpoint(t, f.browser, appConfig.AuthServer.BaseURL+"/auth/token/", url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {f.client.ClientIdentifier},
		"code":          {codeVal},
		"redirect_uri":  {manageAccountRedirectURI},
		"code_verifier": {testCodeVerifier},
	})
	require.NotEmpty(t, data["access_token"], "the token endpoint answers an access token: %v", data)
	return data, code
}

// toIssueSkippingTheScreen follows destUrl from a signed-in browser for a client that asks users for
// consent: /auth/completed sends it to the consent step, which skips the screen and goes on to
// /auth/issue, whose response it answers.
func toIssueSkippingTheScreen(t *testing.T, f *manageAccountConsentFixture, destUrl string) *http.Response {
	t.Helper()

	resp := f.toCompleted(t, destUrl)
	defer func(r *http.Response) { _ = r.Body.Close() }(resp)
	location := assertRedirect(t, resp, "/auth/consent")
	resp = loadPage(t, f.browser, location)
	defer func() { _ = resp.Body.Close() }()
	location = assertRedirect(t, resp, "/auth/issue")
	return loadPage(t, f.browser, location)
}

// silently sends destUrl with prompt=none from the fixture's signed-in browser and answers the
// response.
func silently(t *testing.T, f *manageAccountConsentFixture, destUrl string) *http.Response {
	t.Helper()
	resp, err := f.browser.Get(destUrl + "&prompt=none")
	require.NoError(t, err)
	return resp
}

// The issue's first acceptance item: a public client with Ask users for consent on shows the screen
// on a second sign-in after the user approved every scope, prompt=none is refused with the new
// description, and both skip the screen once an administrator turns Remember consent on.
func TestAuthorize_RememberConsent_APublicClientShowsTheScreenAfterEveryScopeWasApproved(t *testing.T) {
	f := newRememberConsentFixture(t, true, true, false)
	link := f.link("code", "openid profile", "")

	consentURL, page := signInToConsentScreen(t, f, link)
	defer func() { _ = page.Body.Close() }()
	resp := approve(t, f, consentURL, page)
	defer func() { _ = resp.Body.Close() }()
	_, code := redeemPublic(t, f, resp)
	assert.Equal(t, "openid profile", code.Scope)
	require.Equal(t, "openid profile", f.storedConsentScope(t), "the approval is stored")

	t.Run("a second sign-in shows the screen, every scope on it", func(t *testing.T) {
		_, page := f.toConsentScreen(t, link)
		defer func() { _ = page.Body.Close() }()
		assert.Equal(t, []string{"openid", "profile"}, scopesOnScreen(t, page))
	})

	t.Run("prompt=none is answered consent_required with the client's own description", func(t *testing.T) {
		resp := silently(t, f, link)
		defer func() { _ = resp.Body.Close() }()
		assertAnswered(t, resp, "consent_required", rememberConsentDescription)
	})

	require.NoError(t, database.SetClientRememberConsent(context.Background(), nil, f.client.Id, true))

	t.Run("with Remember consent on, the second sign-in skips the screen", func(t *testing.T) {
		resp := toIssueSkippingTheScreen(t, f, link)
		defer func() { _ = resp.Body.Close() }()
		_, code := redeemPublic(t, f, resp)
		assert.Equal(t, "openid profile", code.Scope)
	})

	t.Run("with Remember consent on, prompt=none goes through", func(t *testing.T) {
		resp := silently(t, f, link)
		defer func(r *http.Response) { _ = r.Body.Close() }(resp)
		location := assertRedirect(t, resp, "/auth/issue")
		resp = loadPage(t, f.browser, location)
		defer func() { _ = resp.Body.Close() }()
		_, code := redeemPublic(t, f, resp)
		assert.Equal(t, "openid profile", code.Scope)
	})
}

// A public client with Ask users for consent off and Remember consent off asking for
// authserver:manage-account is shown the screen every time, even after the user approved it, and
// prompt=none for it is refused; asking for nothing that always owes a consent, it signs in as
// before, with no screen and prompt=none answered with a code.
func TestAuthorize_RememberConsent_ManageAccountFromAPublicClientIsAskedEveryTime(t *testing.T) {
	f := newRememberConsentFixture(t, true, false, false)
	f.signIn(t)

	consentURL, page := f.toConsentScreen(t, f.craftedLink("code", ""))
	defer func() { _ = page.Body.Close() }()
	require.Equal(t, []string{"openid", "authserver:manage-account"}, scopesOnScreen(t, page))
	resp := approve(t, f, consentURL, page)
	defer func() { _ = resp.Body.Close() }()
	_, code := redeemPublic(t, f, resp)
	assert.Equal(t, manageAccountScope, code.Scope)
	require.Equal(t, manageAccountScope, f.storedConsentScope(t), "the approval is stored")

	t.Run("the next sign-in asks again", func(t *testing.T) {
		_, page := f.toConsentScreen(t, f.craftedLink("code", ""))
		defer func() { _ = page.Body.Close() }()
		assert.Equal(t, []string{"openid", "authserver:manage-account"}, scopesOnScreen(t, page))
	})

	t.Run("prompt=none for it is answered consent_required with the client's own description", func(t *testing.T) {
		resp := silently(t, f, f.craftedLink("code", ""))
		defer func() { _ = resp.Body.Close() }()
		assertAnswered(t, resp, "consent_required", rememberConsentDescription)
	})

	t.Run("a sign-in owing no consent shows no screen", func(t *testing.T) {
		resp := f.toIssue(t, f.link("code", "openid", ""))
		defer func() { _ = resp.Body.Close() }()
		_, code := redeemPublic(t, f, resp)
		assert.Equal(t, "openid", code.Scope)
	})

	t.Run("prompt=none owing no consent is answered with a code", func(t *testing.T) {
		resp := silently(t, f, f.link("code", "openid", ""))
		defer func(r *http.Response) { _ = r.Body.Close() }(resp)
		location := assertRedirect(t, resp, "/auth/issue")
		resp = loadPage(t, f.browser, location)
		defer func() { _ = resp.Body.Close() }()
		_, code := redeemPublic(t, f, resp)
		assert.Equal(t, "openid", code.Scope)
	})
}

// The refresh grant asks whether the user's consent still exists, not whether to show a screen, so a
// public client with Remember consent off keeps refreshing while the consent given on the screen
// stands; prompt=none asking for offline_access again is refused (#711 decision 2).
func TestAuthorize_RememberConsent_APublicClientRefreshesWhileTheConsentExists(t *testing.T) {
	f := newRememberConsentFixture(t, true, false, false)
	link := f.link("code", "openid offline_access", "")

	consentURL, page := signInToConsentScreen(t, f, link)
	defer func() { _ = page.Body.Close() }()
	resp := approve(t, f, consentURL, page)
	defer func() { _ = resp.Body.Close() }()
	data, _ := redeemPublic(t, f, resp)
	refreshToken, ok := data["refresh_token"].(string)
	require.True(t, ok, "offline_access gives a refresh token: %v", data)

	refreshed := postToTokenEndpoint(t, f.browser, appConfig.AuthServer.BaseURL+"/auth/token/", url.Values{
		"grant_type":    {"refresh_token"},
		"client_id":     {f.client.ClientIdentifier},
		"refresh_token": {refreshToken},
	})
	assert.NotEmpty(t, refreshed["access_token"], "the refresh is answered with tokens: %v", refreshed)
	assert.Nil(t, refreshed["error"])

	t.Run("prompt=none for offline_access is answered consent_required with the client's own description", func(t *testing.T) {
		resp := silently(t, f, link)
		defer func() { _ = resp.Body.Close() }()
		assertAnswered(t, resp, "consent_required", rememberConsentDescription)
	})
}

// A confidential client's stored consent skips the screen as before, whatever its row holds: one
// whose row says Remember consent off, as a row inserted without the column does, still remembers
// (#711 decision 4).
func TestAuthorize_RememberConsent_AConfidentialClientSkipsTheScreenWhateverItsRowHolds(t *testing.T) {
	for _, row := range []bool{true, false} {
		t.Run(map[bool]string{true: "row on", false: "row off"}[row], func(t *testing.T) {
			f := newRememberConsentFixture(t, false, true, row)
			link := f.link("code", "openid profile", "")

			consentURL, page := signInToConsentScreen(t, f, link)
			defer func() { _ = page.Body.Close() }()
			resp := approve(t, f, consentURL, page)
			defer func(r *http.Response) { _ = r.Body.Close() }(resp)
			_, code := f.redeem(t, resp)
			assert.Equal(t, "openid profile", code.Scope)

			resp = toIssueSkippingTheScreen(t, f, link)
			defer func(r *http.Response) { _ = r.Body.Close() }(resp)
			_, code = f.redeem(t, resp)
			assert.Equal(t, "openid profile", code.Scope, "the second sign-in skips the screen")

			resp = silently(t, f, link)
			defer func(r *http.Response) { _ = r.Body.Close() }(resp)
			location := assertRedirect(t, resp, "/auth/issue")
			resp = loadPage(t, f.browser, location)
			defer func(r *http.Response) { _ = r.Body.Close() }(resp)
			_, code = f.redeem(t, resp)
			assert.Equal(t, "openid profile", code.Scope, "prompt=none goes through")
		})
	}
}
