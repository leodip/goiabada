package integration

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/fake"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/api"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A sign-out redirect URI that is plain http on a host other than the loopback interface receives
// nothing (#590 decision 13): /auth/logout signs the user out and leaves them on the
// "Signed out" page with the declined note, and /api/v1/account/logout-request refuses the target
// with 400 rather than hand a caller a sign-out URL that cannot take the user back. RFC 9700
// section 2.6 forbids carrying a response over an unencrypted connection, and RFC 8252 section 7.3's
// loopback exception keeps http to 127.0.0.1, [::1] and localhost working.
//
// No intake accepts such a row (#575), so each test inserts it directly, as migration 000072 does
// when it moves an admin console's plain-http base URL over from its redirect URIs.

// Each test stores its own target, so resolving a client by URI never meets another test's row.
func storedPlainHTTPLogoutTarget() string {
	return "http://rp.example.com/after-logout-" + fake.LetterN(8)
}

func storedLoopbackLogoutTarget() string {
	return "http://127.0.0.1:8123/after-logout-" + fake.LetterN(8)
}

func storeSignOutRedirectURI(t *testing.T, clientId int64, uri string) {
	t.Helper()
	require.NoError(t, database.CreatePostLogoutRedirectURI(context.Background(), nil,
		&record.PostLogoutRedirectURI{ClientId: clientId, URI: uri}))
}

// assertSessionGone asserts the sign-out tore the session down whatever became of the redirect.
func assertSessionGone(t *testing.T, sessionIdentifier string) {
	t.Helper()
	gone, err := database.GetUserSessionBySessionIdentifier(context.Background(), nil, sessionIdentifier)
	require.NoError(t, err)
	assert.Nil(t, gone, "the teardown does not depend on the redirect")
}

func TestLogout_Hintless_AStoredPlainHTTPTargetIsDeclinedButTheLogoutHappens(t *testing.T) {
	grant := createOfflineGrant(t)
	target := storedPlainHTTPLogoutTarget()
	storeSignOutRedirectURI(t, grant.client.Id, target)

	resp := logoutThroughConsentPage(t, grant.httpClient, url.Values{
		"post_logout_redirect_uri": {target},
		"client_id":                {grant.client.ClientIdentifier},
		"state":                    {"abc"},
	})
	defer func() { _ = resp.Body.Close() }()

	require.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Empty(t, resp.Header.Get("Location"), "nothing goes to a plain-http target off loopback")
	assertSignedOutPage(t, resp, signedOutEnglish, true)
	assertSessionGone(t, grant.sessionIdentifier)
}

func TestLogout_WithIdTokenHint_AStoredPlainHTTPTargetIsDeclinedButTheLogoutHappens(t *testing.T) {
	grant := createOfflineGrant(t)
	target := storedPlainHTTPLogoutTarget()
	storeSignOutRedirectURI(t, grant.client.Id, target)
	idToken, _ := sessionBoundGrantOnSameSession(t, grant)

	resp, err := grant.httpClient.Get(appConfig.AuthServer.BaseURL + "/auth/logout?id_token_hint=" + url.QueryEscape(idToken) +
		"&post_logout_redirect_uri=" + url.QueryEscape(target) + "&state=abc")
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	require.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Empty(t, resp.Header.Get("Location"), "nothing goes to a plain-http target off loopback")
	assertSignedOutPage(t, resp, signedOutEnglish, true)
	assertSessionGone(t, grant.sessionIdentifier)
}

func TestLogout_Hintless_AStoredLoopbackHTTPTargetStillRedirects(t *testing.T) {
	grant := createOfflineGrant(t)
	target := storedLoopbackLogoutTarget()
	storeSignOutRedirectURI(t, grant.client.Id, target)

	resp := logoutThroughConsentPage(t, grant.httpClient, url.Values{
		"post_logout_redirect_uri": {target},
		"client_id":                {grant.client.ClientIdentifier},
		"state":                    {"abc"},
	})
	defer func() { _ = resp.Body.Close() }()

	require.Equal(t, http.StatusFound, resp.StatusCode)
	assert.Equal(t, target+"?state=abc", resp.Header.Get("Location"))
	assertSessionGone(t, grant.sessionIdentifier)
}

// The logout request refuses both shapes /auth/logout declines, before resolving the client, by
// identifier or by URI. The wire code is VALIDATION_ERROR like the endpoint's other refusals, and the
// description is the catalog sentence written out here.
func TestAPIAccountLogoutRequest_RefusesATargetLogoutWouldDecline(t *testing.T) {
	_, accessToken, code := getUserAccessTokenAndCodeForAccountScope(t)
	storedPlainHTTP := storedPlainHTTPLogoutTarget()
	storeSignOutRedirectURI(t, code.ClientId, storedPlainHTTP)
	// A row no intake accepts, as #122's legacy redirect URIs were.
	storedSchemeRelative := "//rp.example.com/after-logout-" + fake.LetterN(8)
	storeSignOutRedirectURI(t, code.ClientId, storedSchemeRelative)

	const (
		insecureHTTP = "postLogoutRedirectUri must not use plain http on a host other than the loopback interface (127.0.0.1, [::1] or localhost)"
		notAbsolute  = "postLogoutRedirectUri must be an absolute URI (a scheme is required, a fragment is not permitted, percent-escapes must be well formed, and an http or https URI must name a host)"
	)
	urlLogoutReq := appConfig.AuthServer.BaseURL + "/api/v1/account/logout-request"

	for _, tc := range []struct {
		name             string
		target           string
		clientIdentifier string
		description      string
	}{
		{"a stored plain-http target, named with its client", storedPlainHTTP, code.Client.ClientIdentifier, insecureHTTP},
		{"a stored plain-http target, resolved by URI", storedPlainHTTP, "", insecureHTTP},
		{"a stored scheme-relative target, named with its client", storedSchemeRelative, code.Client.ClientIdentifier, notAbsolute},
		{"a stored scheme-relative target, resolved by URI", storedSchemeRelative, "", notAbsolute},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resp := makeAPIRequest(t, "POST", urlLogoutReq, accessToken, api.AccountLogoutRequest{
				PostLogoutRedirectUri: tc.target,
				ClientIdentifier:      tc.clientIdentifier,
			})
			defer func() { _ = resp.Body.Close() }()

			require.Equal(t, http.StatusBadRequest, resp.StatusCode)
			var out map[string]any
			require.NoError(t, json.NewDecoder(resp.Body).Decode(&out))
			assert.Equal(t, "VALIDATION_ERROR", out["error_code"])
			assert.Equal(t, tc.description, out["error_description"])
			assert.NotContains(t, out, "logoutUrl", "no sign-out URL is handed out for a target logout declines")
		})
	}
}

func TestAPIAccountLogoutRequest_AStoredLoopbackHTTPTargetStillSignsOutAndRedirects(t *testing.T) {
	httpClientWithCookies, accessToken, code := getUserAccessTokenAndCodeForAccountScope(t)
	target := storedLoopbackLogoutTarget()
	storeSignOutRedirectURI(t, code.ClientId, target)

	// Resolved by URI, the path that scans every client's rows.
	resp := makeAPIRequest(t, "POST", appConfig.AuthServer.BaseURL+"/api/v1/account/logout-request", accessToken,
		api.AccountLogoutRequest{PostLogoutRedirectUri: target, State: "abc"})
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	var out api.AccountLogoutRedirectResponse
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&out))

	logoutResp, err := httpClientWithCookies.Get(out.LogoutUrl)
	require.NoError(t, err)
	defer func() { _ = logoutResp.Body.Close() }()

	require.Equal(t, http.StatusFound, logoutResp.StatusCode)
	assert.Equal(t, target+"?state=abc", logoutResp.Header.Get("Location"))
}
