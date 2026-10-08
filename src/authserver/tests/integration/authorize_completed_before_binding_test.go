package integration

import (
	"context"
	"net/http"
	"net/url"
	"strconv"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/fake"
	"github.com/leodip/goiabada/authserver/internal/passwordhash"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/api"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// /auth/completed decides on the user before it binds a session (#522 decision 6). Each case signs
// in for real, has an administrator change the user through the Admin API while the browser is
// between the password step and /auth/completed, and then loads /auth/completed. A disable and a
// password reset both sweep the user's sessions and move their authentication generation on, so a
// session written after either is one nothing can use, and these cases require that none is.

// signedInUpToCompleted is a ceremony whose password was accepted, stopped one hop before
// /auth/completed.
type signedInUpToCompleted struct {
	httpClient   *http.Client
	client       *record.Client
	redirectURI  *record.RedirectURI
	user         *record.User
	state        string
	completedURL string
	// browserSessionId is the browser session's identifier as /auth/completed will receive it.
	// Binding a user session always replaces it, so it is still the browser's afterwards exactly
	// when nothing was bound.
	browserSessionId string
}

// signInUpToCompleted runs a code ceremony as far as the redirect to /auth/completed. The client
// requires consent, so a ceremony that /auth/completed lets through goes on to the consent screen.
func signInUpToCompleted(t *testing.T) *signedInUpToCompleted {
	t.Helper()

	client := &record.Client{
		ClientIdentifier:         "test-client-" + fake.LetterN(8),
		Enabled:                  true,
		AuthorizationCodeEnabled: true,
		ConsentRequired:          true,
		DefaultAcrLevel:          record.AcrLevel1,
	}
	require.NoError(t, database.CreateClient(context.Background(), nil, client))
	t.Cleanup(func() { _ = database.DeleteClient(context.Background(), nil, client.Id) })

	redirectURI := &record.RedirectURI{ClientId: client.Id, URI: fake.URL()}
	require.NoError(t, database.CreateRedirectURI(context.Background(), nil, redirectURI))

	password := fake.Password(10)
	passwordHashed, err := passwordhash.Hash(password)
	require.NoError(t, err)
	user := &record.User{
		Subject:      fake.UUID(),
		Enabled:      true,
		Email:        fake.Email(),
		PasswordHash: passwordHashed,
	}
	require.NoError(t, database.CreateUser(context.Background(), nil, user))
	t.Cleanup(func() { _ = database.DeleteUser(context.Background(), nil, user.Id) })

	state := fake.LetterN(8)
	httpClient := createHttpClient(t)
	resp, err := httpClient.Get(appConfig.AuthServer.BaseURL + "/auth/authorize/?client_id=" + client.ClientIdentifier +
		"&redirect_uri=" + url.QueryEscape(redirectURI.URI) +
		"&response_type=code" +
		"&code_challenge_method=S256" +
		"&code_challenge=" + fake.LetterN(43) +
		"&scope=" + url.QueryEscape("openid profile") +
		"&state=" + state +
		"&nonce=" + fake.LetterN(8))
	require.NoError(t, err)
	_ = resp.Body.Close()

	location := assertRedirect(t, resp, "/auth/level1")
	resp = loadPage(t, httpClient, location)
	_ = resp.Body.Close()

	location = assertRedirect(t, resp, "/auth/pwd")
	pwdPage := loadPage(t, httpClient, location)
	defer func() { _ = pwdPage.Body.Close() }()

	resp = authenticateWithPassword(t, httpClient, location, pwdPage, user.Email, password)
	_ = resp.Body.Close()

	location = assertRedirect(t, resp, "/auth/level1completed")
	resp = loadPage(t, httpClient, location)
	_ = resp.Body.Close()

	return &signedInUpToCompleted{
		httpClient:       httpClient,
		client:           client,
		redirectURI:      redirectURI,
		user:             user,
		state:            state,
		completedURL:     assertRedirect(t, resp, "/auth/completed"),
		browserSessionId: decodeSessionIdentifier(t, requireSessionCookie(t, httpClient)),
	}
}

// loadCompleted loads /auth/completed under a request id of its own, so the audit rows that one
// request left can be read back by it.
func (c *signedInUpToCompleted) loadCompleted(t *testing.T) (*http.Response, string) {
	t.Helper()

	req, err := http.NewRequest(http.MethodGet, c.completedURL, nil)
	require.NoError(t, err)
	requestId := "completed-" + fake.LetterN(16)
	req.Header.Set("X-Request-Id", requestId)
	resp, err := c.httpClient.Do(req)
	require.NoError(t, err)
	return resp, requestId
}

// assertNothingWasBound is the three traces a bound session leaves, each required absent: the
// session row, the browser session rotated onto it, and the record of its start.
func (c *signedInUpToCompleted) assertNothingWasBound(t *testing.T, adminToken, requestId string) {
	t.Helper()

	assert.Empty(t, sessionsThroughAdminAPI(t, adminToken, c.user.Id), "no session row is written")
	assert.Equal(t, c.browserSessionId, decodeSessionIdentifier(t, requireSessionCookie(t, c.httpClient)),
		"the browser session is not rotated onto a user session")
	assert.Empty(t, auditRows(t, adminToken, "started_new_user_session", requestId),
		"no session start is recorded")
}

// A user an administrator disables between the password step and /auth/completed is answered
// access_denied, as before, and nothing is bound first.
func TestAuthCompleted_AUserDisabledMidSignInGetsNoSession(t *testing.T) {
	requireDatabaseAuditLogs(t)
	adminToken, adminClient := createAdminClientWithToken(t)
	t.Cleanup(func() { _ = database.DeleteClient(context.Background(), nil, adminClient.Id) })

	signIn := signInUpToCompleted(t)

	resp := makeAPIRequest(t, http.MethodPut, appConfig.AuthServer.BaseURL+"/api/v1/admin/users/"+
		strconv.FormatInt(signIn.user.Id, 10)+"/enabled", adminToken, api.UpdateUserEnabledRequest{Enabled: false})
	require.Equal(t, http.StatusOK, resp.StatusCode)
	_ = resp.Body.Close()

	resp, requestId := signIn.loadCompleted(t)
	defer func() { _ = resp.Body.Close() }()

	destination, params := clientAnswer(t, resp, "code")
	assert.Equal(t, signIn.redirectURI.URI, destination)
	assert.Equal(t, "access_denied", params.Get("error"))
	assert.Equal(t, "The user account is disabled.", params.Get("error_description"))
	assert.Equal(t, signIn.state, params.Get("state"))
	assert.Empty(t, params.Get("code"))

	assert.Len(t, auditRows(t, adminToken, "user_disabled", requestId), 1, "the refusal is recorded")
	signIn.assertNothingWasBound(t, adminToken, requestId)
}

// A user whose password an administrator resets between the password step and /auth/completed is
// sent back to sign in with the new one: no session is written, and no consent screen is shown
// whose answer /auth/issue would throw away.
func TestAuthCompleted_APasswordResetMidSignInRestartsTheSignIn(t *testing.T) {
	requireDatabaseAuditLogs(t)
	adminToken, adminClient := createAdminClientWithToken(t)
	t.Cleanup(func() { _ = database.DeleteClient(context.Background(), nil, adminClient.Id) })

	signIn := signInUpToCompleted(t)

	newPassword := "newSecurePassword123!" + fake.LetterN(4)
	resp := makeAPIRequest(t, http.MethodPut, appConfig.AuthServer.BaseURL+"/api/v1/admin/users/"+
		strconv.FormatInt(signIn.user.Id, 10)+"/password", adminToken, api.UpdateUserPasswordRequest{NewPassword: newPassword})
	require.Equal(t, http.StatusOK, resp.StatusCode)
	_ = resp.Body.Close()

	resp, requestId := signIn.loadCompleted(t)
	defer func() { _ = resp.Body.Close() }()

	restart := assertRedirect(t, resp, "/auth/level1")
	assert.NotContains(t, restart, signIn.redirectURI.URI, "the client is told nothing")
	signIn.assertNothingWasBound(t, adminToken, requestId)

	// A real restart: the password form again, which takes the new password and goes on to the
	// consent screen this client requires.
	next := loadPage(t, signIn.httpClient, restart)
	_ = next.Body.Close()
	location := assertRedirect(t, next, "/auth/pwd")
	pwdPage := loadPage(t, signIn.httpClient, location)
	defer func() { _ = pwdPage.Body.Close() }()

	next = authenticateWithPassword(t, signIn.httpClient, location, pwdPage, signIn.user.Email, newPassword)
	_ = next.Body.Close()
	location = assertRedirect(t, next, "/auth/level1completed")
	next = loadPage(t, signIn.httpClient, location)
	_ = next.Body.Close()
	location = assertRedirect(t, next, "/auth/completed")
	next = loadPage(t, signIn.httpClient, location)
	_ = next.Body.Close()
	assertRedirect(t, next, "/auth/consent")

	assert.Len(t, sessionsThroughAdminAPI(t, adminToken, signIn.user.Id), 1,
		"the second pass binds the one session")
}
