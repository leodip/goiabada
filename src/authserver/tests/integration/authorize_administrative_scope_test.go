package integration

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/PuerkitoBio/goquery"
	"github.com/leodip/goiabada/authserver/internal/audit"
	"github.com/leodip/goiabada/authserver/internal/fake"
	"github.com/leodip/goiabada/authserver/internal/passwordhash"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/builtin"
	"github.com/leodip/goiabada/core/oauth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The crafted link of #499, driven end to end. An ordinary client with consent off sends a signed-in
// administrator a link asking for authserver:manage; before #499 it got a code, and from it a token
// carrying the administrator's whole Admin API authority, with no screen shown. Now only a client
// allowed to request the administrative scopes may obtain one, and any other is answered
// invalid_scope with no code, through the paths every validation failure at /auth/authorize already
// takes: at once to a signed-in browser and to prompt=none, after the sign-in to a signed-out one
// (#499 decisions 1, 7 and 9).

// administrativeScopeRedirectURI is the crafted link's client's callback, with no query of its own
// so the answer can be compared as a string.
const administrativeScopeRedirectURI = "https://crafted.example.com/callback"

// administrativeScopeRefusal is the refusal's description, byte for byte, as #499 decision 7 words it.
const administrativeScopeRefusal = "The client is not allowed to request the administrative scope 'authserver:manage'."

// administrativeScopeState is the state the crafted link carries.
const administrativeScopeState = "crafted-state"

// administrativeScopeFixture is an administrator, a browser, and a consent-off client with the
// authorization code flow and the implicit grant on, administrator-registered so its redirects are
// emitted.
type administrativeScopeFixture struct {
	client   *record.Client
	user     *record.User
	password string
	browser  *http.Client
}

func newAdministrativeScopeFixture(t *testing.T, allowed bool) *administrativeScopeFixture {
	t.Helper()

	implicit := true
	client := &record.Client{
		ClientIdentifier:            "crafted-link-client-" + fake.LetterN(8),
		Enabled:                     true,
		AuthorizationCodeEnabled:    true,
		ImplicitGrantEnabled:        &implicit,
		ConsentRequired:             false,
		DefaultAcrLevel:             record.AcrLevel1,
		AdministrativeScopesAllowed: allowed,
	}
	require.NoError(t, database.CreateClient(context.Background(), nil, client))
	t.Cleanup(func() { _ = database.DeleteClient(context.Background(), nil, client.Id) })
	require.NoError(t, database.CreateRedirectURI(context.Background(), nil,
		&record.RedirectURI{ClientId: client.Id, URI: administrativeScopeRedirectURI}))

	user, password := newSignInAdministrator(t)
	return &administrativeScopeFixture{client: client, user: user, password: password, browser: createHttpClient(t)}
}

// newSignInAdministrator is a user holding authserver:manage, and its password.
func newSignInAdministrator(t *testing.T) (*record.User, string) {
	t.Helper()

	password := fake.Password(10)
	passwordHashed, err := passwordhash.Hash(password)
	require.NoError(t, err)
	user := &record.User{Subject: fake.UUID(), Enabled: true, Email: fake.Email(), PasswordHash: passwordHashed}
	require.NoError(t, database.CreateUser(context.Background(), nil, user))
	t.Cleanup(func() { _ = database.DeleteUser(context.Background(), nil, user.Id) })
	assignPermissionToUser(t, user.Id, authServerPermissionId(t, builtin.ManagePermissionIdentifier))
	return user, password
}

// craftedLink is the authorization request the issue describes, for responseType, with extra
// appended as it is.
func (f *administrativeScopeFixture) craftedLink(responseType string, extra string) string {
	destUrl := appConfig.AuthServer.BaseURL + "/auth/authorize/?client_id=" + f.client.ClientIdentifier +
		"&redirect_uri=" + url.QueryEscape(administrativeScopeRedirectURI) +
		"&response_type=" + url.QueryEscape(responseType) +
		"&scope=" + url.QueryEscape("openid authserver:manage") +
		"&state=" + administrativeScopeState +
		"&nonce=" + fake.LetterN(8)
	if responseType == "code" {
		destUrl += "&code_challenge_method=S256&code_challenge=" + oauth.GeneratePKCECodeChallenge(testCodeVerifier)
	}
	return destUrl + extra
}

// signIn gives the browser a valid session, through the same client asking for openid alone, which
// is what an administrator who used this client before holds.
func (f *administrativeScopeFixture) signIn(t *testing.T) {
	t.Helper()

	destUrl := appConfig.AuthServer.BaseURL + "/auth/authorize/?client_id=" + f.client.ClientIdentifier +
		"&redirect_uri=" + url.QueryEscape(administrativeScopeRedirectURI) +
		"&response_type=code&scope=openid&state=sign-in" +
		"&code_challenge_method=S256&code_challenge=" + oauth.GeneratePKCECodeChallenge(testCodeVerifier)
	resp := f.signInFrom(t, destUrl)
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusFound, resp.StatusCode)
	require.Contains(t, resp.Header.Get("Location"), "code=", "the sign-in completes with a code")
}

// signInFrom drives a ceremony that needs the password from its authorization request to
// /auth/issue, and answers /auth/issue's response.
func (f *administrativeScopeFixture) signInFrom(t *testing.T, destUrl string) *http.Response {
	t.Helper()

	resp, err := f.browser.Get(destUrl)
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
	return loadPage(t, f.browser, location)
}

// get loads destUrl in the fixture's browser without following redirects.
func (f *administrativeScopeFixture) get(t *testing.T, destUrl string) *http.Response {
	t.Helper()
	resp, err := f.browser.Get(destUrl)
	require.NoError(t, err)
	return resp
}

// administrativeScopeRefusedRows is the administrative_scope_refused rows naming clientIdentifier.
func administrativeScopeRefusedRows(t *testing.T, clientIdentifier string) []map[string]any {
	t.Helper()

	readerToken, readerClient := createAdminClientWithToken(t)
	t.Cleanup(func() { _ = database.DeleteClient(context.Background(), nil, readerClient.Id) })
	logs, resp := getAuditLogs(t, readerToken, "auditEvent="+audit.EventAdministrativeScopeRefused+"&size=200")
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	rows := []map[string]any{}
	for _, entry := range logs.AuditLogs {
		var details map[string]any
		require.NoError(t, json.Unmarshal([]byte(entry.Details), &details))
		if details["client_identifier"] == clientIdentifier {
			rows = append(rows, details)
		}
	}
	return rows
}

// assertRefusedAtAuthorize holds the rows naming the fixture's client to the one row a refusal at
// /auth/authorize leaves for a signed-in browser.
func (f *administrativeScopeFixture) assertRefusedAtAuthorize(t *testing.T) {
	t.Helper()
	rows := administrativeScopeRefusedRows(t, f.client.ClientIdentifier)
	require.Len(t, rows, 1, "one row for the refusal")
	assert.Equal(t, map[string]any{
		"client_id":         float64(f.client.Id),
		"client_identifier": f.client.ClientIdentifier,
		"scopes":            []any{"authserver:manage"},
		"checkpoint":        "authorize",
		"user_id":           float64(f.user.Id),
	}, rows[0])
}

// The issue's scenario: a signed-in administrator follows the link. The client is answered at once,
// as any refused request from a signed-in browser is, with invalid_scope and no code, and the attempt
// is recorded against the administrator it was aimed at.
func TestAuthorize_AdministrativeScope_RefusedForASignedInBrowser(t *testing.T) {
	requireDatabaseAuditLogs(t)
	f := newAdministrativeScopeFixture(t, false)
	f.signIn(t)

	resp := f.get(t, f.craftedLink("code", ""))
	defer func() { _ = resp.Body.Close() }()

	require.Equal(t, http.StatusFound, resp.StatusCode)
	assert.Equal(t, administrativeScopeRedirectURI+"?error=invalid_scope"+
		"&error_description="+url.QueryEscape(administrativeScopeRefusal)+
		"&state="+administrativeScopeState, resp.Header.Get("Location"))
	f.assertRefusedAtAuthorize(t)
}

// prompt=none: nothing is displayed and the client is answered at once (OIDC Core 3.1.2.1), the
// same refusal and the same row.
func TestAuthorize_AdministrativeScope_RefusedForPromptNone(t *testing.T) {
	requireDatabaseAuditLogs(t)
	f := newAdministrativeScopeFixture(t, false)
	f.signIn(t)

	resp := f.get(t, f.craftedLink("code", "&prompt=none"))
	defer func() { _ = resp.Body.Close() }()

	require.Equal(t, http.StatusFound, resp.StatusCode)
	assert.Equal(t, administrativeScopeRedirectURI+"?error=invalid_scope"+
		"&error_description="+url.QueryEscape(administrativeScopeRefusal)+
		"&state="+administrativeScopeState, resp.Header.Get("Location"))
	f.assertRefusedAtAuthorize(t)
}

// The implicit flow is refused at the same check, in the fragment, with no token.
func TestAuthorize_AdministrativeScope_RefusedForTheImplicitFlow(t *testing.T) {
	requireDatabaseAuditLogs(t)
	f := newAdministrativeScopeFixture(t, false)
	f.signIn(t)

	for _, responseType := range []string{"token", "id_token token"} {
		t.Run(responseType, func(t *testing.T) {
			resp := f.get(t, f.craftedLink(responseType, ""))
			defer func() { _ = resp.Body.Close() }()

			require.Equal(t, http.StatusFound, resp.StatusCode)
			assert.Equal(t, administrativeScopeRedirectURI+"#error=invalid_scope"+
				"&error_description="+url.QueryEscape(administrativeScopeRefusal)+
				"&state="+administrativeScopeState, resp.Header.Get("Location"))
		})
	}

	rows := administrativeScopeRefusedRows(t, f.client.ClientIdentifier)
	require.Len(t, rows, 2, "one row for each refusal")
	for _, row := range rows {
		assert.Equal(t, "authorize", row["checkpoint"])
		assert.Equal(t, float64(f.user.Id), row["user_id"])
	}
}

// A signed-out browser is not redirected anywhere before it signs in (RFC 9700 4.11.2): the refusal
// is parked behind the password and delivered after it, the ceremony creating no session and no
// code. Nobody had authenticated when the request was refused, so it leaves no audit row.
func TestAuthorize_AdministrativeScope_RefusedForASignedOutBrowserAfterTheSignIn(t *testing.T) {
	requireDatabaseAuditLogs(t)
	f := newAdministrativeScopeFixture(t, false)

	resp := driveDeferral(t, f.browser, f.craftedLink("code", ""), f.user, f.password)
	defer func() { _ = resp.Body.Close() }()

	require.Equal(t, http.StatusFound, resp.StatusCode)
	assert.Equal(t, administrativeScopeRedirectURI+"?error=invalid_scope"+
		"&error_description="+url.QueryEscape(administrativeScopeRefusal)+
		"&state="+administrativeScopeState, resp.Header.Get("Location"))
	assert.Empty(t, administrativeScopeRefusedRows(t, f.client.ClientIdentifier),
		"a refusal nobody had authenticated for leaves no audit row")
}

// The same link from a client an operator has allowed gets its code, carrying the scope.
func TestAuthorize_AdministrativeScope_AnAllowedClientGetsTheCode(t *testing.T) {
	requireDatabaseAuditLogs(t)
	f := newAdministrativeScopeFixture(t, true)

	resp := f.signInFrom(t, f.craftedLink("code", ""))
	defer func() { _ = resp.Body.Close() }()

	codeVal, state := getCodeAndStateFromUrl(t, resp)
	assert.Equal(t, administrativeScopeState, state)
	code := loadCodeFromDatabase(t, codeVal)
	assert.Equal(t, "openid authserver:manage", code.Scope)
	assert.Equal(t, f.user.Id, code.User.Id)
	assert.Empty(t, administrativeScopeRefusedRows(t, f.client.ClientIdentifier))
}

// The admin console's own client signs in exactly as it did: its usual scopes, the response mode it
// uses, no consent screen, and a code carrying authserver:manage (#499 decisions 1 and 5).
func TestAuthorize_AdministrativeScope_TheAdminConsoleClientSignsInWithNoConsentScreen(t *testing.T) {
	user, password := newSignInAdministrator(t)
	browser := createHttpClient(t)
	callback := appConfig.AdminConsole.BaseURL + "/auth/callback"

	// The admin console's request, as middleware_jwt.go's buildScopeString and auth_helper.go's
	// RedirToAuthorize build it.
	const scope = "authserver:manage authserver:manage-account email openid profile"
	state := fake.LetterN(16)
	destUrl := appConfig.AuthServer.BaseURL + "/auth/authorize?" + url.Values{
		"client_id":             {builtin.AdminConsoleClientIdentifier},
		"redirect_uri":          {callback},
		"response_mode":         {"form_post"},
		"response_type":         {"code"},
		"code_challenge_method": {"S256"},
		"code_challenge":        {oauth.GeneratePKCECodeChallenge(testCodeVerifier)},
		"state":                 {state},
		"nonce":                 {fake.LetterN(16)},
		"scope":                 {scope},
	}.Encode()

	resp, err := browser.Get(destUrl)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	location := assertRedirect(t, resp, "/auth/level1")
	resp = loadPage(t, browser, location)
	defer func() { _ = resp.Body.Close() }()
	location = assertRedirect(t, resp, "/auth/pwd")
	resp = loadPage(t, browser, location)
	defer func() { _ = resp.Body.Close() }()
	resp = authenticateWithPassword(t, browser, location, resp, user.Email, password)
	defer func() { _ = resp.Body.Close() }()
	location = assertRedirect(t, resp, "/auth/level1completed")
	resp = loadPage(t, browser, location)
	defer func() { _ = resp.Body.Close() }()
	// level2_optional, and the user has no authenticator, so level 2 is skipped.
	location = assertRedirect(t, resp, "/auth/level2")
	resp = loadPage(t, browser, location)
	defer func() { _ = resp.Body.Close() }()
	location = assertRedirect(t, resp, "/auth/completed")
	resp = loadPage(t, browser, location)
	defer func() { _ = resp.Body.Close() }()
	// Straight to /auth/issue: no consent screen.
	location = assertRedirect(t, resp, "/auth/issue")
	resp = loadPage(t, browser, location)
	defer func() { _ = resp.Body.Close() }()

	require.Equal(t, http.StatusOK, resp.StatusCode, "form_post answers with the auto-submitting page")
	doc, err := goquery.NewDocumentFromReader(resp.Body)
	require.NoError(t, err)
	codeVal, ok := doc.Find(`input[name="code"]`).Attr("value")
	require.True(t, ok, "the page posts a code")
	postedState, _ := doc.Find(`input[name="state"]`).Attr("value")
	assert.Equal(t, state, postedState)
	assert.True(t, strings.HasPrefix(doc.Find("form").AttrOr("action", ""), callback))

	code := loadCodeFromDatabase(t, codeVal)
	assert.Equal(t, builtin.AdminConsoleClientIdentifier, code.Client.ClientIdentifier)
	assert.Contains(t, strings.Fields(code.Scope), "authserver:manage")
	assert.Equal(t, user.Id, code.User.Id)
}
