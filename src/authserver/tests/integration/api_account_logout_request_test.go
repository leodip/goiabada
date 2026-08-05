package integrationtests

import (
	"encoding/json"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/brianvoe/gofakeit/v6"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/config"
	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Helper to get a user access token with account scope and also the auth code details (client, redirect, sid)
// Returns (httpClientWithCookies, accessToken, code)
func getUserAccessTokenAndCodeForAccountScope(t *testing.T) (*http.Client, string, *models.Code) {
	scope := "openid profile email " + constants.AuthServerResourceIdentifier + ":" + constants.ManageAccountPermissionIdentifier
	clientSecret := gofakeit.LetterN(32)
	httpClient, code := createAuthCodeEnsuringUserScope(t, clientSecret, scope)

	// Exchange code for tokens using the same client to preserve cookies for session
	tokenEndpoint := config.GetAuthServer().BaseURL + "/auth/token/"
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {code.Client.ClientIdentifier},
		"client_secret": {clientSecret},
		"code":          {code.Code},
		"redirect_uri":  {code.RedirectURI},
		"code_verifier": {"code-verifier"},
	}
	data := postToTokenEndpoint(t, httpClient, tokenEndpoint, form)
	accessToken, ok := data["access_token"].(string)
	assert.True(t, ok)
	assert.NotEmpty(t, accessToken)
	return httpClient, accessToken, code
}

func TestAPIAccountLogoutRequest_Success_And_LogoutFlow_WithAndWithoutCookie(t *testing.T) {
	// Arrange: create session and token with account scope
	httpClientWithCookies, accessToken, code := getUserAccessTokenAndCodeForAccountScope(t)

	// Request logout URL
	reqBody := api.AccountLogoutRequest{
		PostLogoutRedirectUri: code.RedirectURI,
		State:                 gofakeit.LetterN(12),
		ResponseMode:          "redirect",
	}
	urlLogoutReq := config.GetAuthServer().BaseURL + "/api/v1/account/logout-request"
	resp := makeAPIRequest(t, "POST", urlLogoutReq, accessToken, reqBody)
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var out api.AccountLogoutRedirectResponse
	err := json.NewDecoder(resp.Body).Decode(&out)
	assert.NoError(t, err)
	assert.NotEmpty(t, out.LogoutUrl)

	// Parse returned logout URL and verify parameters
	u, err := url.Parse(out.LogoutUrl)
	assert.NoError(t, err)
	assert.Equal(t, "/auth/logout", u.Path)
	q := u.Query()
	assert.NotEmpty(t, q.Get("id_token_hint"))
	assert.Equal(t, code.RedirectURI, q.Get("post_logout_redirect_uri"))
	assert.Equal(t, reqBody.State, q.Get("state"))

	// 1) Call /auth/logout with cookies: expect 302 to post_logout_redirect with sid present
	req1, _ := http.NewRequest("GET", out.LogoutUrl, nil)
	resp1, err := httpClientWithCookies.Do(req1)
	assert.NoError(t, err)
	defer func() { _ = resp1.Body.Close() }()
	assert.Equal(t, http.StatusFound, resp1.StatusCode)
	loc1, err := url.Parse(resp1.Header.Get("Location"))
	assert.NoError(t, err)
	assert.Equal(t, code.RedirectURI, loc1.Scheme+"://"+loc1.Host+loc1.Path)
	assert.Equal(t, reqBody.State, loc1.Query().Get("state"))
	assert.Equal(t, code.SessionIdentifier, loc1.Query().Get("sid"))

	// 2) Call /auth/logout without cookies (new client): expect 302 with sid from id_token_hint (fallback)
	httpClientNoCookies := createHttpClient(t)
	req2, _ := http.NewRequest("GET", out.LogoutUrl, nil)
	resp2, err := httpClientNoCookies.Do(req2)
	assert.NoError(t, err)
	defer func() { _ = resp2.Body.Close() }()
	assert.Equal(t, http.StatusFound, resp2.StatusCode)
	loc2, err := url.Parse(resp2.Header.Get("Location"))
	assert.NoError(t, err)
	assert.Equal(t, code.RedirectURI, loc2.Scheme+"://"+loc2.Host+loc2.Path)
	assert.Equal(t, reqBody.State, loc2.Query().Get("state"))
	assert.Equal(t, code.SessionIdentifier, loc2.Query().Get("sid"))
}

// The two cases below pin that #129 changed NOTHING about RP-initiated logout (decision 3). The
// dividing line is intent: "end this session" is a security action aimed at a device, logout is
// navigation, and the fact that logout happens to delete the session row when the departing client
// was the only one on it is bookkeeping rather than a revocation decision.
//
// THEY ARE DRIVEN THROUGH REQUEST SHAPES #109 IS NOT REWRITING, per decision 13. Both supply
// id_token_hint AND post_logout_redirect_uri, because #109's first item is that the second is wrongly
// treated as required and its check returns before the teardown. They assert only what #129 cares
// about, that no grant was revoked, and nothing about whether that parameter should be required, how
// the redirect was built, or whether the session row survives, which is #109 divergence B's business.
//
// The hint comes from the token exchange's own id_token rather than from /api/v1/account/logout-request,
// so these cases do not depend on that endpoint's client resolution, which is also #109's surface.

// logoutWithHint performs the RP-initiated logout for a grant's client and returns nothing but a
// completed teardown: it fails the test unless the server redirected to the post-logout URI, which is
// what stops a "nothing was revoked" assertion passing because logout did nothing at all.
func logoutWithHint(t *testing.T, grant *offlineGrant, idToken string) {
	t.Helper()

	state := gofakeit.LetterN(10)
	logoutURL := config.GetAuthServer().BaseURL + "/auth/logout?id_token_hint=" + url.QueryEscape(idToken) +
		"&post_logout_redirect_uri=" + url.QueryEscape(grant.redirectURI) +
		"&state=" + state

	resp, err := grant.httpClient.Get(logoutURL)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusFound, resp.StatusCode, "logout should redirect")

	location, err := url.Parse(resp.Header.Get("Location"))
	require.NoError(t, err)
	require.Equal(t, grant.redirectURI, location.Scheme+"://"+location.Host+location.Path,
		"the teardown must have run to completion, not stopped at an error page")
	require.Equal(t, state, location.Query().Get("state"))
}

// sessionBoundGrantOnSameSession runs a second authorization on the grant's live session WITHOUT
// offline_access and returns its id_token and refresh token. The id_token is what logout matches
// against the session, and the refresh token is session bound, so it is the one whose survival
// decision 3's second claim is about.
func sessionBoundGrantOnSameSession(t *testing.T, grant *offlineGrant) (string, string) {
	t.Helper()

	const codeVerifier = "code-verifier-logout"
	scope := "openid " + constants.AuthServerResourceIdentifier + ":" + constants.ManageAccountPermissionIdentifier
	exchanged := grant.exchange(t, grant.codeFromSameSession(t, scope, codeVerifier), codeVerifier)

	idToken, ok := exchanged["id_token"].(string)
	require.True(t, ok, "expected an id_token to use as the logout hint: %v", exchanged)
	require.Equal(t, grant.sessionIdentifier, claimString(t, idToken, "sid"),
		"the hint must name the session logout is being asked to tear down")

	refreshToken, ok := exchanged["refresh_token"].(string)
	require.True(t, ok, "a session-bound auth code grant must yield a refresh token: %v", exchanged)
	return idToken, refreshToken
}

// TestLogout_WithIdTokenHint_RevokesNoGrants is decision 3's first claim: an offline grant survives
// logout in every case, including the one where logout deletes the session row because the departing
// client was the only one on it.
func TestLogout_WithIdTokenHint_RevokesNoGrants(t *testing.T) {
	grant := createOfflineGrant(t)

	first := grant.refresh(t)
	require.NotEmpty(t, first["access_token"], "the grant should refresh before logout: %v", first)
	grant.refreshToken = first["refresh_token"].(string)

	idToken, _ := sessionBoundGrantOnSameSession(t, grant)
	logoutWithHint(t, grant, idToken)

	after := grant.refresh(t)
	assert.NotEmpty(t, after["access_token"],
		"logout must revoke nothing, decision 3: %v", after)
}

// TestLogout_WithIdTokenHint_OtherClientOnSession_KeepsSessionBoundTokensWorking is decision 3's
// second claim, which is the more surprising one and the reason it is pinned: the client that just
// logged out keeps a working session-bound refresh token, because the session row survives while
// another client remains on it and nothing in refresh validation reads the client-session link.
//
// Pinned so #135, "disconnect this application", has to change it deliberately rather than by
// accident.
func TestLogout_WithIdTokenHint_OtherClientOnSession_KeepsSessionBoundTokensWorking(t *testing.T) {
	grant := createOfflineGrant(t)
	idToken, sessionBoundRefresh := sessionBoundGrantOnSameSession(t, grant)

	session, err := database.GetUserSessionBySessionIdentifier(nil, grant.sessionIdentifier)
	require.NoError(t, err)
	require.NotNil(t, session)

	// A second client on the same session, created directly as this suite already does for its
	// session listings. What handleExistingSessionOnLogout reads is the NUMBER of clients on the
	// session, not how each got there.
	otherClient := &models.Client{
		ClientIdentifier:         "logout-other-" + gofakeit.LetterN(8),
		ClientSecretEncrypted:    []byte("encrypted-secret"),
		Description:              "Second client sharing the session",
		Enabled:                  true,
		AuthorizationCodeEnabled: true,
	}
	require.NoError(t, database.CreateClient(nil, otherClient))
	defer func() { _ = database.DeleteClient(nil, otherClient.Id) }()

	now := time.Now().UTC()
	require.NoError(t, database.CreateUserSessionClient(nil, &models.UserSessionClient{
		UserSessionId: session.Id,
		ClientId:      otherClient.Id,
		Started:       now.Add(-time.Hour),
		LastAccessed:  now.Add(-5 * time.Minute),
	}))

	logoutWithHint(t, grant, idToken)

	data := postToTokenEndpoint(t, createHttpClient(t), config.GetAuthServer().BaseURL+"/auth/token/", url.Values{
		"grant_type":    {"refresh_token"},
		"client_id":     {grant.client.ClientIdentifier},
		"client_secret": {grant.clientSecret},
		"refresh_token": {sessionBoundRefresh},
	})
	assert.NotEmpty(t, data["access_token"],
		"the logged-out client's session-bound refresh token must keep working while another client shares the session: %v", data)
}

func TestAPIAccountLogoutRequest_ValidationErrors_And_Scope(t *testing.T) {
	_, accessToken, _ := getUserAccessTokenAndCodeForAccountScope(t)
	urlLogoutReq := config.GetAuthServer().BaseURL + "/api/v1/account/logout-request"

	// Missing postLogoutRedirectUri
	resp1 := makeAPIRequest(t, "POST", urlLogoutReq, accessToken, map[string]string{})
	defer func() { _ = resp1.Body.Close() }()
	assert.Equal(t, http.StatusBadRequest, resp1.StatusCode)
	var err1 api.ErrorResponse
	_ = json.NewDecoder(resp1.Body).Decode(&err1)
	assert.Equal(t, "postLogoutRedirectUri is required", err1.ErrorDescription)

	// Unresolvable postLogoutRedirectUri (no client matches)
	badReq := api.AccountLogoutRequest{PostLogoutRedirectUri: "https://invalid.example/"}
	resp2 := makeAPIRequest(t, "POST", urlLogoutReq, accessToken, badReq)
	defer func() { _ = resp2.Body.Close() }()
	assert.Equal(t, http.StatusBadRequest, resp2.StatusCode)
	var err2 api.ErrorResponse
	_ = json.NewDecoder(resp2.Body).Decode(&err2)
	assert.Equal(t, "Unable to resolve client from postLogoutRedirectUri; supply clientIdentifier.", err2.ErrorDescription)

	// Scope and auth checks
	// No token
	reqNoTok, _ := http.NewRequest("POST", urlLogoutReq, nil)
	httpClient := createHttpClient(t)
	resp3, err := httpClient.Do(reqNoTok)
	assert.NoError(t, err)
	defer func() { _ = resp3.Body.Close() }()
	assert.Equal(t, http.StatusUnauthorized, resp3.StatusCode)

	// Insufficient scope
	tok := createClientCredentialsTokenWithScope(t, constants.AuthServerResourceIdentifier, constants.UserinfoPermissionIdentifier)
	resp4 := makeAPIRequest(t, "POST", urlLogoutReq, tok, api.AccountLogoutRequest{PostLogoutRedirectUri: "https://example.com/"})
	defer func() { _ = resp4.Body.Close() }()
	assert.Equal(t, http.StatusForbidden, resp4.StatusCode)
}
