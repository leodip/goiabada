package integration

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/authserver/internal/fake"
	"github.com/leodip/goiabada/authserver/internal/record"
)

// A client set to "Require DPoP for token requests" is refused the response types that return an
// access token, "token" and "id_token token", with unauthorized_client (RFC 6749 section 4.2.2.1,
// #42 decision 13): an implicit access token leaves in the redirect, with no token request and so
// no proof. It is refused when the request is validated and again at issuance, so the requirement
// switched on while a user is mid-sign-in still applies. "id_token" alone returns no access token
// and is answered as before.

// implicitDPoPRefusal is the description of that refusal.
const implicitDPoPRefusal = "This client requires DPoP for its access tokens, so it can't receive one through the " +
	"implicit grant. Use the authorization code flow with PKCE instead."

// implicitAuthorizeURL is an implicit authorization request for client.
func implicitAuthorizeURL(client *record.Client, redirectURI, responseType, state string) string {
	return appConfig.AuthServer.BaseURL + "/auth/authorize/?client_id=" + client.ClientIdentifier +
		"&redirect_uri=" + url.QueryEscape(redirectURI) +
		"&response_type=" + url.QueryEscape(responseType) +
		"&scope=openid" +
		"&state=" + state +
		"&nonce=" + fake.LetterN(16)
}

// signInToIssueAsANewUser follows a fresh browser's ceremony from the authorization request to the redirect
// /auth/completed answers, and returns the /auth/issue location, before it is loaded.
func signInToIssueAsANewUser(t *testing.T, httpClient *http.Client, authorizeURL string) string {
	t.Helper()
	user, password := createTestUserForImplicit(t)

	resp, err := httpClient.Get(authorizeURL)
	require.NoError(t, err)
	defer func(r *http.Response) { _ = r.Body.Close() }(resp)
	redirectLocation := assertRedirect(t, resp, "/auth/level1")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func(r *http.Response) { _ = r.Body.Close() }(resp)
	redirectLocation = assertRedirect(t, resp, "/auth/pwd")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func(r *http.Response) { _ = r.Body.Close() }(resp)
	resp = authenticateWithPassword(t, httpClient, redirectLocation, resp, user.Email, password)
	defer func(r *http.Response) { _ = r.Body.Close() }(resp)
	redirectLocation = assertRedirect(t, resp, "/auth/level1completed")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func(r *http.Response) { _ = r.Body.Close() }(resp)
	redirectLocation = assertRedirect(t, resp, "/auth/completed")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func(r *http.Response) { _ = r.Body.Close() }(resp)
	return assertRedirect(t, resp, "/auth/issue")
}

// newImplicitClientRequiringDPoP is an implicit client with the grant on for itself, requiring DPoP
// as given, deleted when the test ends.
func newImplicitClientRequiringDPoP(t *testing.T, requires bool) (*record.Client, string) {
	t.Helper()
	implicitEnabled := true
	client, redirectURI := createImplicitFlowClient(t, &implicitEnabled)
	t.Cleanup(func() { _ = database.DeleteClient(context.Background(), nil, client.Id) })
	if requires {
		require.NoError(t, database.SetClientDPoPBoundAccessTokens(context.Background(), nil, client.Id, true))
	}
	return client, redirectURI.URI
}

func TestImplicitDPoPRequirement_AnAccessTokenIsRefusedAtTheAuthorizationRequest(t *testing.T) {
	client, redirectURI := newImplicitClientRequiringDPoP(t, true)

	for _, responseType := range []string{"token", "id_token token"} {
		t.Run(responseType, func(t *testing.T) {
			state := fake.LetterN(16)
			resp, err := createAuthenticatedHttpClient(t).Get(implicitAuthorizeURL(client, redirectURI, responseType, state))
			require.NoError(t, err)
			defer func() { _ = resp.Body.Close() }()

			require.Equal(t, http.StatusFound, resp.StatusCode)
			assert.True(t, strings.HasPrefix(resp.Header.Get("Location"), redirectURI+"#"), "answered to the client, in the fragment")
			errorCode, errorDescription, answeredState := getErrorFromFragment(t, resp)
			assert.Equal(t, "unauthorized_client", errorCode)
			assert.Equal(t, implicitDPoPRefusal, errorDescription)
			assert.Equal(t, state, answeredState)
		})
	}
}

func TestImplicitDPoPRequirement_AnIDTokenAloneIsIssued(t *testing.T) {
	client, redirectURI := newImplicitClientRequiringDPoP(t, true)
	httpClient := createHttpClient(t)

	issue := signInToIssueAsANewUser(t, httpClient, implicitAuthorizeURL(client, redirectURI, "id_token", fake.LetterN(16)))
	resp := loadPage(t, httpClient, issue)
	defer func() { _ = resp.Body.Close() }()

	require.Equal(t, http.StatusFound, resp.StatusCode)
	tokens := getTokensFromFragment(t, resp)
	assert.NotEmpty(t, tokens["id_token"])
	assert.Empty(t, tokens["access_token"])
	assert.Empty(t, tokens["error"])
}

// The requirement switched on after the request was validated, while the user signs in, is applied
// at issuance: nothing is issued, and the client is told why.
func TestImplicitDPoPRequirement_SwitchedOnMidSignInIsAppliedAtIssuance(t *testing.T) {
	for _, responseType := range []string{"token", "id_token token"} {
		t.Run(responseType, func(t *testing.T) {
			client, redirectURI := newImplicitClientRequiringDPoP(t, false)
			httpClient := createHttpClient(t)
			state := fake.LetterN(16)

			issue := signInToIssueAsANewUser(t, httpClient, implicitAuthorizeURL(client, redirectURI, responseType, state))
			require.NoError(t, database.SetClientDPoPBoundAccessTokens(context.Background(), nil, client.Id, true))
			resp := loadPage(t, httpClient, issue)
			defer func() { _ = resp.Body.Close() }()

			require.Equal(t, http.StatusFound, resp.StatusCode)
			errorCode, errorDescription, answeredState := getErrorFromFragment(t, resp)
			assert.Equal(t, "unauthorized_client", errorCode)
			assert.Equal(t, implicitDPoPRefusal, errorDescription)
			assert.Equal(t, state, answeredState)
			assert.NotContains(t, resp.Header.Get("Location"), "access_token=")
		})
	}
}
