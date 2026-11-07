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

// #244's remaining parts over HTTP: what the authorization and token endpoints now refuse or ignore,
// each shown end to end. The validators own every spelling and byte edge; these show each rule is
// reached on the wire, and that the refusal is the one the client reads.

// authorizeRequest is a code-flow authorization request for client, its parameters overridable.
func authorizeRequest(client *record.Client, redirectUri *record.RedirectURI, overrides map[string]string) string {
	query := url.Values{
		"client_id":             {client.ClientIdentifier},
		"redirect_uri":          {redirectUri.URI},
		"response_type":         {"code"},
		"code_challenge_method": {"S256"},
		"code_challenge":        {randomCodeChallenge()},
		"scope":                 {"openid profile"},
		"state":                 {fake.LetterN(8)},
	}
	for name, value := range overrides {
		query.Set(name, value)
	}
	return appConfig.AuthServer.BaseURL + "/auth/authorize/?" + query.Encode()
}

// answeredAtOnce sends the request from a browser that holds a session, which answers a refusal on
// the redirect itself (#213), and returns that redirect.
func answeredAtOnce(t *testing.T, destUrl string) *http.Response {
	t.Helper()
	httpClient := createAuthenticatedHttpClient(t)

	resp, err := httpClient.Get(destUrl)
	require.NoError(t, err)
	t.Cleanup(func() { _ = resp.Body.Close() })

	require.Equal(t, http.StatusFound, resp.StatusCode)
	return resp
}

// A response_type that repeats a value or names an unknown one is unsupported_response_type. Each
// used to be collapsed into the request it resembled and accepted as the code flow.
func TestAuthorize_ResponseTypeSpellingsAreRefused(t *testing.T) {
	client, redirectUri := createTestClientAndRedirectURI(t)

	for name, responseType := range map[string]string{
		"a repeated value":                     "code code",
		"an unknown value beside code":         "code foo",
		"an unknown value before code":         "foo code",
		"two types joined by a no-break space": "code token",
	} {
		t.Run(name, func(t *testing.T) {
			resp := answeredAtOnce(t, authorizeRequest(client, redirectUri, map[string]string{"response_type": responseType}))

			errorCode, description, _ := getErrorFromUrl(t, resp)

			assert.Equal(t, "unsupported_response_type", errorCode)
			assert.Equal(t, "The authorization server does not support this response_type. Supported values: code, token, id_token, id_token token.", description)
		})
	}

	// The control: the same request with a plain "code" is not refused, so it is the spelling.
	t.Run("code alone goes on to the login", func(t *testing.T) {
		resp, err := createHttpClient(t).Get(authorizeRequest(client, redirectUri, nil))
		require.NoError(t, err)
		defer func() { _ = resp.Body.Close() }()

		assertRedirect(t, resp, "/auth/level1")
	})
}

// An S256 code_challenge is BASE64URL(SHA256(verifier)) (RFC 7636 4.2): exactly 43 characters of the
// base64url alphabet, the canonical form of 32 bytes. Anything else could never equal the hash the
// token endpoint computes and used to fail only at the exchange, after the user had signed in; it is
// refused where it enters (#714, #42 decision 20).
func TestAuthorize_AnImpossibleS256ChallengeIsRefused(t *testing.T) {
	const (
		// RFC 7636 appendix B's challenge. Its last character, 'M', is 001100: the two spare bits
		// a canonical encoding leaves zero.
		realChallenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
		// The client takes the global setting, which requires PKCE.
		description = "The code_challenge parameter is either missing or incorrect. It must be the SHA-256 hash of the code_verifier, base64url-encoded without padding: 43 characters of A-Z, a-z, 0-9, '-' and '_'."
	)
	client, redirectUri := createTestClientAndRedirectURI(t)

	for name, challenge := range map[string]string{
		"the lower spare bit set":  realChallenge[:42] + "N",
		"the higher spare bit set": realChallenge[:42] + "O",
		"padding":                  realChallenge + "=",
		"42 characters":            realChallenge[:42],
		"44 characters":            realChallenge + "A",
		"128 characters":           strings.Repeat("aZ09-_", 21) + "aZ",
		"a period":                 realChallenge[:20] + "." + realChallenge[21:],
		"a tilde":                  realChallenge[:20] + "~" + realChallenge[21:],
		"a plus":                   realChallenge[:20] + "+" + realChallenge[21:],
		"a slash":                  realChallenge[:20] + "/" + realChallenge[21:],
		"a CR":                     realChallenge[:20] + "\r" + realChallenge[21:],
		"an LF":                    realChallenge + "\n",
		"a space":                  " " + realChallenge,
		"a tab":                    realChallenge[:20] + "\t" + realChallenge[21:],
		"non-ASCII":                realChallenge[:41] + "é",
	} {
		t.Run(name, func(t *testing.T) {
			resp := answeredAtOnce(t, authorizeRequest(client, redirectUri, map[string]string{"code_challenge": challenge}))

			errorCode, gotDescription, _ := getErrorFromUrl(t, resp)

			assert.Equal(t, "invalid_request", errorCode)
			assert.Equal(t, description, gotDescription)
		})
	}

	// A real challenge, and RFC 7638 section 3.1's thumbprint, another SHA-256 value in the same
	// form, go on to the login.
	for name, challenge := range map[string]string{
		"a real challenge":          realChallenge,
		"a real SHA-256 thumbprint": "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs",
	} {
		t.Run("accepts "+name, func(t *testing.T) {
			resp, err := createHttpClient(t).Get(authorizeRequest(client, redirectUri, map[string]string{"code_challenge": challenge}))
			require.NoError(t, err)
			defer func() { _ = resp.Body.Close() }()

			assertRedirect(t, resp, "/auth/level1")
		})
	}
}

// A scope of offline_access alone names no resource and no claim. It used to be accepted, and the
// code exchange then answered 500 after it had claimed the code; it is refused as an invalid scope.
func TestAuthorize_OfflineAccessAloneIsRefused(t *testing.T) {
	const description = "The 'scope' parameter holds only 'offline_access', which grants nothing by itself. Include at least one other scope, such as 'openid' or a resource:permission scope."

	t.Run("in the code flow", func(t *testing.T) {
		client, redirectUri := createTestClientAndRedirectURI(t)

		resp := answeredAtOnce(t, authorizeRequest(client, redirectUri, map[string]string{"scope": "offline_access"}))

		errorCode, errorDescription, _ := getErrorFromUrl(t, resp)
		assert.Equal(t, "invalid_scope", errorCode)
		assert.Equal(t, description, errorDescription)
	})

	t.Run("in the implicit flow, in the fragment, where the response type ignores it and leaves nothing", func(t *testing.T) {
		enabled := true
		client, redirectUri := createImplicitFlowClient(t, &enabled)

		resp := answeredAtOnce(t, authorizeRequest(client, redirectUri, map[string]string{
			"response_type": "token", "scope": "offline_access", "code_challenge": "", "code_challenge_method": "",
		}))

		errorCode, errorDescription, _ := getErrorFromFragment(t, resp)
		assert.Equal(t, "invalid_scope", errorCode)
		assert.Equal(t, description, errorDescription)
	})

	// offline_access beside another scope is a fine request, so it is the absence of the other scope
	// that was refused.
	t.Run("beside openid is served", func(t *testing.T) {
		client, redirectUri := createTestClientAndRedirectURI(t)

		resp, err := createHttpClient(t).Get(authorizeRequest(client, redirectUri, map[string]string{"scope": "openid offline_access"}))
		require.NoError(t, err)
		defer func() { _ = resp.Body.Close() }()

		assertRedirect(t, resp, "/auth/level1")
	})
}

// OIDC Core 11: offline_access is ignored unless the response type returns a code. An implicit
// sign-in that asks for it is served without the consent screen offline_access forces on a code
// flow, and the tokens' scope claim does not carry it.
func TestAuthorize_ImplicitIgnoresOfflineAccess(t *testing.T) {
	enabled := true
	client, redirectUri := createImplicitFlowClient(t, &enabled)
	user, password := createTestUserForImplicit(t)

	requestState := fake.LetterN(16)
	destUrl := appConfig.AuthServer.BaseURL + "/auth/authorize/?client_id=" + client.ClientIdentifier +
		"&redirect_uri=" + url.QueryEscape(redirectUri.URI) +
		"&response_type=token" +
		"&scope=" + url.QueryEscape("openid offline_access") +
		"&state=" + requestState

	httpClient := createHttpClient(t)

	resp, err := httpClient.Get(destUrl)
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

	// /auth/issue, not /auth/consent: a code flow with offline_access in its scope is always sent
	// to the consent screen, and this ceremony was not.
	redirectLocation = assertRedirect(t, resp, "/auth/issue")
	resp = loadPage(t, httpClient, redirectLocation)
	defer func() { _ = resp.Body.Close() }()

	require.Equal(t, http.StatusFound, resp.StatusCode)
	tokens := getTokensFromFragment(t, resp)
	require.NotEmpty(t, tokens["access_token"])
	assert.Equal(t, requestState, tokens["state"])
	assert.Empty(t, tokens["refresh_token"])

	scope, _ := decodeJWTPayload(t, tokens["access_token"])["scope"].(string)
	assert.Contains(t, strings.Fields(scope), "openid")
	assert.NotContains(t, strings.Fields(scope), "offline_access",
		"the response type returns no code, so offline_access is ignored (OIDC Core 11)")
}

// A code_verifier outside RFC 7636 4.1's grammar is refused invalid_grant before the comparison
// (RFC 7636 4.6), naming the rule, and the refusal does not consume the code: a caller that then
// presents the right verifier redeems it.
func TestToken_AuthCode_MalformedCodeVerifierIsRefusedAndTheCodeStaysRedeemable(t *testing.T) {
	clientSecret := fake.LetterN(32)
	_, code := createAuthCode(t, clientSecret, "openid profile")

	const description = "The code_verifier parameter is incorrect. It should be 43 to 128 characters long and may only contain A-Z, a-z, 0-9, '-', '.', '_' and '~'."

	form := func(verifier string) url.Values {
		return url.Values{
			"grant_type":    {"authorization_code"},
			"client_id":     {code.Client.ClientIdentifier},
			"client_secret": {clientSecret},
			"code":          {code.Code},
			"redirect_uri":  {code.RedirectURI},
			"code_verifier": {verifier},
		}
	}

	for name, verifier := range map[string]string{
		"one character short":       testCodeVerifier[:42],
		"one character too long":    strings.Repeat("a", 129),
		"a plus":                    testCodeVerifier[:20] + "+" + testCodeVerifier[21:],
		"a space":                   testCodeVerifier[:20] + " " + testCodeVerifier[21:],
		"padding":                   testCodeVerifier[:50] + "=",
		"a two-byte character":      testCodeVerifier[:41] + "é",
		"30 well-formed characters": testCodeVerifier[:30],
		"32 hex characters":         strings.Repeat("0123456789abcdef", 2),
	} {
		t.Run(name, func(t *testing.T) {
			status, body := postFormToTokenEndpoint(t, form(verifier))

			assertTokenRefusal(t, status, body, http.StatusBadRequest, "invalid_grant", description)

			stored, err := database.GetCodeById(context.Background(), nil, code.Id)
			require.NoError(t, err)
			assert.False(t, stored.Used, "a verifier that is not one must not consume the code")
		})
	}

	// A well-formed verifier that does not match keeps the comparison's own answer, so the grammar
	// check is not what answers it.
	t.Run("a well-formed verifier that does not match", func(t *testing.T) {
		status, body := postFormToTokenEndpoint(t, form(testCodeVerifier+"-not-the-one"))

		assertTokenRefusal(t, status, body, http.StatusBadRequest, "invalid_grant", "Invalid code_verifier (PKCE).")
	})

	t.Run("the right verifier redeems the code after all of those", func(t *testing.T) {
		status, body := postFormToTokenEndpoint(t, form(testCodeVerifier))

		assert.Equal(t, http.StatusOK, status)
		assert.NotEmpty(t, body["access_token"])
	})
}
