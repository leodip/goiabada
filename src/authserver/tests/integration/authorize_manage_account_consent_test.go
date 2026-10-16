package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/PuerkitoBio/goquery"
	"github.com/leodip/goiabada/authserver/internal/fake"
	"github.com/leodip/goiabada/authserver/internal/passwordhash"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/builtin"
	"github.com/leodip/goiabada/core/oauth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The crafted link of #509, driven end to end. An ordinary client with consent off sends a
// signed-in user a link asking for openid authserver:manage-account; before #509 it got a code, and
// from it a token the Account API accepts, with no screen shown. Now a client other than the admin
// console's gets authserver:manage-account only once the user has consented to it, whatever its
// Consent required says: an interactive sign-in stops at the consent screen and prompt=none is
// answered consent_required (#509 decisions 1 to 3).

// manageAccountRedirectURI is the crafted link's client's callback.
const manageAccountRedirectURI = "https://manage-account.example.com/callback"

// manageAccountState is the state the crafted link carries.
const manageAccountState = "crafted-state"

// manageAccountScope is the crafted link's scope, spelled as the issue spells it.
const manageAccountScope = "openid authserver:manage-account"

// manageAccountConsentFixture is a user holding manage-account, as every user does from creation,
// a browser, and a confidential consent-off client with the authorization code flow and the
// implicit grant on.
type manageAccountConsentFixture struct {
	client       *record.Client
	clientSecret string
	user         *record.User
	password     string
	browser      *http.Client
}

func newManageAccountConsentFixture(t *testing.T, administrativeScopesAllowed bool) *manageAccountConsentFixture {
	t.Helper()

	clientSecret := fake.LetterN(32)
	clientSecretEncrypted, err := dataCipher.Encrypt(clientSecret)
	require.NoError(t, err)
	implicit := true
	client := &record.Client{
		ClientIdentifier:            "manage-account-client-" + fake.LetterN(8),
		Enabled:                     true,
		AuthorizationCodeEnabled:    true,
		ImplicitGrantEnabled:        &implicit,
		ConsentRequired:             false,
		DefaultAcrLevel:             record.AcrLevel1,
		ClientSecretEncrypted:       clientSecretEncrypted,
		AdministrativeScopesAllowed: administrativeScopesAllowed,
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

// link is an authorization request from the fixture's client for scope and responseType, with
// extra appended as it is.
func (f *manageAccountConsentFixture) link(responseType, scope, extra string) string {
	destUrl := appConfig.AuthServer.BaseURL + "/auth/authorize/?client_id=" + f.client.ClientIdentifier +
		"&redirect_uri=" + url.QueryEscape(manageAccountRedirectURI) +
		"&response_type=" + url.QueryEscape(responseType) +
		"&scope=" + url.QueryEscape(scope) +
		"&state=" + manageAccountState +
		"&nonce=" + fake.LetterN(8)
	if responseType == "code" {
		destUrl += "&code_challenge_method=S256&code_challenge=" + oauth.GeneratePKCECodeChallenge(testCodeVerifier)
	}
	return destUrl + extra
}

// craftedLink is the issue's link, for responseType.
func (f *manageAccountConsentFixture) craftedLink(responseType, extra string) string {
	return f.link(responseType, manageAccountScope, extra)
}

// signIn gives the browser a valid session, through the same client asking for openid alone, which
// is owed no consent screen from a consent-off client and leaves no stored consent.
func (f *manageAccountConsentFixture) signIn(t *testing.T) {
	t.Helper()

	resp, err := f.browser.Get(f.link("code", "openid", ""))
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	location := assertRedirect(t, resp, "/auth/level1")
	resp = loadPage(t, f.browser, location)
	defer func() { _ = resp.Body.Close() }()
	location = assertRedirect(t, resp, "/auth/pwd")
	resp = loadPage(t, f.browser, location)
	defer func() { _ = resp.Body.Close() }()
	resp = authenticateWithPassword(t, f.browser, location, resp, f.user.Email, f.password)
	defer func() { _ = resp.Body.Close() }()
	location = assertRedirect(t, resp, "/auth/level1completed")
	resp = loadPage(t, f.browser, location)
	defer func() { _ = resp.Body.Close() }()
	location = assertRedirect(t, resp, "/auth/completed")
	resp = loadPage(t, f.browser, location)
	defer func() { _ = resp.Body.Close() }()
	location = assertRedirect(t, resp, "/auth/issue")
	resp = loadPage(t, f.browser, location)
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusFound, resp.StatusCode)
	require.Contains(t, resp.Header.Get("Location"), "code=", "the sign-in completes with a code")

	consent, err := database.GetConsentByUserIdAndClientId(context.Background(), nil, f.user.Id, f.client.Id)
	require.NoError(t, err)
	require.Nil(t, consent, "the sign-in leaves no stored consent")
}

// toCompleted follows destUrl from a signed-in browser through the SSO shortcut to /auth/completed,
// and answers /auth/completed's response.
func (f *manageAccountConsentFixture) toCompleted(t *testing.T, destUrl string) *http.Response {
	t.Helper()

	resp, err := f.browser.Get(destUrl)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	location := assertRedirect(t, resp, "/auth/level1completed")
	resp = loadPage(t, f.browser, location)
	defer func() { _ = resp.Body.Close() }()
	location = assertRedirect(t, resp, "/auth/completed")
	return loadPage(t, f.browser, location)
}

// toConsentScreen follows destUrl from a signed-in browser to the consent screen, and answers its
// URL and the rendered page.
func (f *manageAccountConsentFixture) toConsentScreen(t *testing.T, destUrl string) (string, *http.Response) {
	t.Helper()

	resp := f.toCompleted(t, destUrl)
	defer func() { _ = resp.Body.Close() }()
	location := assertRedirect(t, resp, "/auth/consent")
	page := loadPage(t, f.browser, location)
	require.Equal(t, http.StatusOK, page.StatusCode, "the consent screen is rendered")
	return location, page
}

// toIssue follows destUrl from a signed-in browser straight through /auth/completed to /auth/issue,
// with no consent screen, and answers /auth/issue's response.
func (f *manageAccountConsentFixture) toIssue(t *testing.T, destUrl string) *http.Response {
	t.Helper()

	resp := f.toCompleted(t, destUrl)
	defer func() { _ = resp.Body.Close() }()
	location := assertRedirect(t, resp, "/auth/issue")
	return loadPage(t, f.browser, location)
}

// scopesOnScreen is the scopes the consent page lists, in its order, each with its checkbox's
// index. The page's body is re-buffered so the submission can still read its ceremony id.
func scopesOnScreen(t *testing.T, page *http.Response) []string {
	t.Helper()

	body, err := io.ReadAll(page.Body)
	require.NoError(t, err)
	page.Body = io.NopCloser(bytes.NewReader(body))
	doc, err := goquery.NewDocumentFromReader(bytes.NewReader(body))
	require.NoError(t, err)
	var scopes []string
	doc.Find(`label[for^="consent"]`).Each(func(_ int, label *goquery.Selection) {
		scopes = append(scopes, strings.TrimSpace(label.Text()))
	})
	return scopes
}

// storedConsentScope is the scope of the user's stored consent to the client, or "" for none.
func (f *manageAccountConsentFixture) storedConsentScope(t *testing.T) string {
	t.Helper()
	consent, err := database.GetConsentByUserIdAndClientId(context.Background(), nil, f.user.Id, f.client.Id)
	require.NoError(t, err)
	if consent == nil {
		return ""
	}
	return consent.Scope
}

// redeem exchanges the code /auth/issue answered for an access token.
func (f *manageAccountConsentFixture) redeem(t *testing.T, issueResponse *http.Response) (string, *record.Code) {
	t.Helper()

	codeVal, state := getCodeAndStateFromUrl(t, issueResponse)
	assert.Equal(t, manageAccountState, state)
	code := loadCodeFromDatabase(t, codeVal)
	data := postToTokenEndpoint(t, f.browser, appConfig.AuthServer.BaseURL+"/auth/token/", url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {f.client.ClientIdentifier},
		"client_secret": {f.clientSecret},
		"code":          {codeVal},
		"redirect_uri":  {manageAccountRedirectURI},
		"code_verifier": {testCodeVerifier},
	})
	accessToken, ok := data["access_token"].(string)
	require.True(t, ok, "the token endpoint answers an access token: %v", data)
	return accessToken, code
}

// assertTheAccountAPIAccepts holds accessToken to reading the fixture user's profile.
func (f *manageAccountConsentFixture) assertTheAccountAPIAccepts(t *testing.T, accessToken string) {
	t.Helper()

	resp := makeAPIRequest(t, "GET", appConfig.AuthServer.BaseURL+"/api/v1/account/profile", accessToken, nil)
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var profile api.GetUserResponse
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&profile))
	assert.Equal(t, f.user.Id, profile.User.Id)
}

// assertAnswered holds /auth/issue's or /auth/authorize's response to the client's callback with
// errorCode and errorDescription in the query, the state echoed, and no code.
func assertAnswered(t *testing.T, resp *http.Response, errorCode, errorDescription string) {
	t.Helper()
	require.Equal(t, ceremonyRedirectStatus(resp), resp.StatusCode)
	location := resp.Header.Get("Location")
	require.True(t, strings.HasPrefix(location, manageAccountRedirectURI+"?"), "answered at the client's callback: %s", location)
	gotCode, gotDescription, gotState := getErrorFromUrl(t, resp)
	assert.Equal(t, errorCode, gotCode)
	assert.Equal(t, errorDescription, gotDescription)
	assert.Equal(t, manageAccountState, gotState)
	assert.NotContains(t, location, "code=")
}

// The issue's scenario: a signed-in user follows the link. It stops at the consent screen, which
// lists both scopes; approving gives a code carrying both and a token the Account API accepts, and
// the answer is kept, so the next sign-in and a prompt=none request go through with no screen.
func TestAuthorize_ManageAccount_TheCraftedLinkStopsAtTheConsentScreen(t *testing.T) {
	f := newManageAccountConsentFixture(t, false)
	f.signIn(t)

	consentURL, page := f.toConsentScreen(t, f.craftedLink("code", ""))
	defer func() { _ = page.Body.Close() }()
	require.Equal(t, []string{"openid", "authserver:manage-account"}, scopesOnScreen(t, page))

	resp := postConsent(t, f.browser, consentURL, page, []int{0, 1})
	defer func() { _ = resp.Body.Close() }()
	location := assertRedirect(t, resp, "/auth/issue")
	resp = loadPage(t, f.browser, location)
	defer func() { _ = resp.Body.Close() }()

	accessToken, code := f.redeem(t, resp)
	assert.Equal(t, manageAccountScope, code.Scope)
	f.assertTheAccountAPIAccepts(t, accessToken)
	assert.Equal(t, manageAccountScope, f.storedConsentScope(t), "the answer is kept")

	t.Run("a second sign-in goes through with no screen", func(t *testing.T) {
		resp := f.toIssue(t, f.craftedLink("code", ""))
		defer func() { _ = resp.Body.Close() }()
		_, code := f.redeem(t, resp)
		assert.Equal(t, manageAccountScope, code.Scope)
	})

	t.Run("prompt=none goes through with no screen", func(t *testing.T) {
		resp, err := f.browser.Get(f.craftedLink("code", "&prompt=none"))
		require.NoError(t, err)
		defer func() { _ = resp.Body.Close() }()
		location := assertRedirect(t, resp, "/auth/issue")
		resp = loadPage(t, f.browser, location)
		defer func() { _ = resp.Body.Close() }()
		_, code := f.redeem(t, resp)
		assert.Equal(t, manageAccountScope, code.Scope)
	})
}

// Cancelling the screen answers the client access_denied with no code, and stores nothing.
func TestAuthorize_ManageAccount_CancellingTheConsentScreenAnswersAccessDenied(t *testing.T) {
	f := newManageAccountConsentFixture(t, false)
	f.signIn(t)

	consentURL, page := f.toConsentScreen(t, f.craftedLink("code", ""))
	defer func() { _ = page.Body.Close() }()
	resp := postConsent(t, f.browser, consentURL, page, nil)
	defer func() { _ = resp.Body.Close() }()

	assertAnswered(t, resp, "access_denied", "The user did not provide consent")
	assert.Empty(t, f.storedConsentScope(t), "a cancel stores no consent")
}

// Unticking manage-account gives a code without it, and since the stored consent leaves it out, a
// prompt=none request for it is answered "Additional consent is required" and the next sign-in asks
// again.
func TestAuthorize_ManageAccount_UntickingItLeavesItOutAndTheNextSignInAsksAgain(t *testing.T) {
	f := newManageAccountConsentFixture(t, false)
	f.signIn(t)

	consentURL, page := f.toConsentScreen(t, f.craftedLink("code", ""))
	defer func() { _ = page.Body.Close() }()
	require.Equal(t, []string{"openid", "authserver:manage-account"}, scopesOnScreen(t, page))
	resp := postConsent(t, f.browser, consentURL, page, []int{0})
	defer func() { _ = resp.Body.Close() }()
	location := assertRedirect(t, resp, "/auth/issue")
	resp = loadPage(t, f.browser, location)
	defer func() { _ = resp.Body.Close() }()

	_, code := f.redeem(t, resp)
	assert.Equal(t, "openid", code.Scope, "the code leaves manage-account out")
	assert.Equal(t, "openid", f.storedConsentScope(t))

	t.Run("prompt=none is answered Additional consent is required", func(t *testing.T) {
		resp, err := f.browser.Get(f.craftedLink("code", "&prompt=none"))
		require.NoError(t, err)
		defer func() { _ = resp.Body.Close() }()
		assertAnswered(t, resp, "consent_required", "Additional consent is required")
	})

	t.Run("the next sign-in asks again", func(t *testing.T) {
		_, page := f.toConsentScreen(t, f.craftedLink("code", ""))
		defer func() { _ = page.Body.Close() }()
		assert.Equal(t, []string{"openid", "authserver:manage-account"}, scopesOnScreen(t, page))
	})
}

// prompt=none with no stored consent: nothing may be displayed, so the client is answered
// consent_required at once (OIDC Core 1.0 section 3.1.2.1), with no code.
func TestAuthorize_ManageAccount_PromptNoneWithNoConsentAnswersConsentRequired(t *testing.T) {
	f := newManageAccountConsentFixture(t, false)
	f.signIn(t)

	resp, err := f.browser.Get(f.craftedLink("code", "&prompt=none"))
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	assertAnswered(t, resp, "consent_required", "User consent is required")
}

// The implicit flow stops at the same screen, and approving gives an access token the Account API
// accepts.
func TestAuthorize_ManageAccount_TheImplicitFlowStopsAtTheConsentScreen(t *testing.T) {
	f := newManageAccountConsentFixture(t, false)
	f.signIn(t)

	consentURL, page := f.toConsentScreen(t, f.craftedLink("token", ""))
	defer func() { _ = page.Body.Close() }()
	require.Equal(t, []string{"openid", "authserver:manage-account"}, scopesOnScreen(t, page))

	resp := postConsent(t, f.browser, consentURL, page, []int{0, 1})
	defer func() { _ = resp.Body.Close() }()
	location := assertRedirect(t, resp, "/auth/issue")
	resp = loadPage(t, f.browser, location)
	defer func() { _ = resp.Body.Close() }()

	require.Equal(t, http.StatusFound, resp.StatusCode)
	tokens := getTokensFromFragment(t, resp)
	assert.Equal(t, manageAccountState, tokens["state"])
	require.NotEmpty(t, tokens["access_token"])
	f.assertTheAccountAPIAccepts(t, tokens["access_token"])
}

// A client an operator allowed to request the administrative scopes (#499) is asked like any other:
// the allowance means only that (#509 decision 2).
func TestAuthorize_ManageAccount_AClientAllowedAdministrativeScopesIsAskedLikeAnyOther(t *testing.T) {
	f := newManageAccountConsentFixture(t, true)
	f.signIn(t)

	_, page := f.toConsentScreen(t, f.craftedLink("code", ""))
	defer func() { _ = page.Body.Close() }()
	assert.Equal(t, []string{"openid", "authserver:manage-account"}, scopesOnScreen(t, page))

	resp, err := f.browser.Get(f.craftedLink("code", "&prompt=none"))
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	assertAnswered(t, resp, "consent_required", "User consent is required")
}
