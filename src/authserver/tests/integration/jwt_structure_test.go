package integration

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/fake"
	"github.com/leodip/goiabada/authserver/internal/idtokenhint"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// #709 findings 1 to 4 through the real stack: the auth server's parser refuses a token whose
// structure is invalid before its signature is checked, and every endpoint that reads a token
// answers such a token exactly as it answers one that is not a JWT at all. The tokens here are the
// server's own, altered only in their serialization, so the signature they carry is good. The
// header and claim cases (crit, cty, invalid UTF-8) need a token signed with altered content, which
// only the unit tier can sign; the alphabet cases are the ones a client can send.

const malformedAccessTokenChallenge = `Bearer realm="goiabada", error="invalid_token", error_description="The access token is invalid."` + ", " + dpopChallengeBare

// = padding is outside the compact serialization's unpadded alphabet (RFC 7515 section 2). Sent in
// the Authorization header, the padded token is refused at userinfo and the admin API as a token that
// is not a JWT is.
func TestJWTStructure_APaddedAccessTokenIsRefusedAsMalformed(t *testing.T) {
	userToken, user := createUserAccessTokenWithScope(t, "openid profile")
	adminToken, _ := createAdminClientWithToken(t)

	accepted := sendBearerRequest(t, "GET", "/userinfo", "Bearer "+userToken, "")
	require.Equal(t, http.StatusOK, accepted.status, accepted.body)
	assert.Contains(t, accepted.body, user.Subject, "the unaltered token is accepted")
	acceptedAdmin := sendBearerRequest(t, "GET", bearerRFC6750AdminRoute, "Bearer "+adminToken, "")
	require.Equal(t, http.StatusOK, acceptedAdmin.status, acceptedAdmin.body)

	malformed := sendBearerRequest(t, "GET", "/userinfo", "Bearer not-a-token", "")
	assert.Equal(t, http.StatusUnauthorized, malformed.status)
	assert.Equal(t, malformedAccessTokenChallenge, malformed.challenge)
	assert.JSONEq(t, `{"error":"invalid_token","error_description":"The access token is invalid."}`, malformed.body)
	malformedAdmin := sendBearerRequest(t, "GET", bearerRFC6750AdminRoute, "Bearer not-a-token", "")
	assert.Equal(t, http.StatusUnauthorized, malformedAdmin.status)
	assert.Equal(t, malformedAccessTokenChallenge, malformedAdmin.challenge)

	for name, padded := range map[string]func(string) string{
		"= on the signature":  func(token string) string { return token + "=" },
		"== on the signature": func(token string) string { return token + "==" },
		"= on the payload": func(token string) string {
			parts := strings.Split(token, ".")
			return parts[0] + "." + parts[1] + "=." + parts[2]
		},
	} {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, malformed, sendBearerRequest(t, "GET", "/userinfo", "Bearer "+padded(userToken), ""),
				"userinfo answers the padded token as it answers one that is no JWT")
			assert.Equal(t, malformedAdmin, sendBearerRequest(t, "GET", bearerRFC6750AdminRoute, "Bearer "+padded(adminToken), ""),
				"the admin API answers the padded token as it answers one that is no JWT")
		})
	}
}

// A line break inside a segment is outside the alphabet too (RFC 7515 section 5.2). HTTP refuses CR
// and LF in a header field, so the token is sent where a form body carries it, which is how it
// reaches the parser: the access_token body parameter at userinfo, the token at introspection, and
// the refresh_token at the refresh grant. Go's base64 decoder skips CR and LF, so before this the
// token verified and each of the three accepted it.
func TestJWTStructure_ATokenWithALineBreakIsRefusedAsMalformed(t *testing.T) {
	data, code, httpClient, clientSecret := userTokenResponseWithScope(t, "openid profile", nil)
	t.Cleanup(func() { _ = database.DeleteClient(context.Background(), nil, code.ClientId) })
	accessToken := data["access_token"].(string)
	refreshToken := data["refresh_token"].(string)
	require.NotEmpty(t, refreshToken)

	breaks := map[string]func(string) string{
		"an LF after the signature":  func(token string) string { return token + "\n" },
		"a CRLF after the signature": func(token string) string { return token + "\r\n" },
		"an LF inside the signature": func(token string) string {
			at := strings.LastIndex(token, ".") + 20
			return token[:at] + "\n" + token[at:]
		},
	}

	t.Run("userinfo", func(t *testing.T) {
		malformed := sendBearerRequest(t, "POST", "/userinfo", "", url.Values{"access_token": {"not-a-token"}}.Encode())
		assert.Equal(t, http.StatusUnauthorized, malformed.status)
		assert.Equal(t, malformedAccessTokenChallenge, malformed.challenge)
		for name, broken := range breaks {
			answer := sendBearerRequest(t, "POST", "/userinfo", "", url.Values{"access_token": {broken(accessToken)}}.Encode())
			assert.Equal(t, malformed, answer, "%s: answered as a token that is no JWT", name)
		}
		accepted := sendBearerRequest(t, "POST", "/userinfo", "", url.Values{"access_token": {accessToken}}.Encode())
		require.Equal(t, http.StatusOK, accepted.status, accepted.body)
		assert.Contains(t, accepted.body, code.User.Subject, "the unaltered token is accepted")
	})

	t.Run("introspection", func(t *testing.T) {
		api := authserverAPI(t)
		for name, broken := range breaks {
			t.Run(name, func(t *testing.T) {
				assertInactive(t, api.introspect(t, broken(accessToken)))
			})
		}
		assertActive(t, api.introspect(t, accessToken))
	})

	t.Run("the refresh grant", func(t *testing.T) {
		for name, broken := range breaks {
			status, body := replayRefreshToken(t, httpClient, code.Client.ClientIdentifier, clientSecret, broken(refreshToken))
			assertRefusedAsInvalidGrant(t, status, body, name)
			assert.Equal(t, "The refresh token is invalid.", body["error_description"], name)
		}

		// A malformed token revokes nothing, so the unaltered one still refreshes.
		status, body := replayRefreshToken(t, httpClient, code.Client.ClientIdentifier, clientSecret, refreshToken)
		require.Equal(t, http.StatusOK, status, "%v", body)
		assert.NotEmpty(t, body["access_token"])
	})
}

// An encrypted id_token_hint is decrypted first, and its inner ID token is then read by the parser,
// so the structural check applies to that inner signed token and not to the encrypted envelope. A
// hint whose inner token carries a line break is refused as the wrong-secret hint is: the End-User
// is asked, and the redirect is refused. The same hint with the unaltered token still signs out
// without asking (TestLogout_WithEncryptedIdTokenHint_LogsTheUserOut).
func TestJWTStructure_AnEncryptedHintWithAMalformedInnerTokenIsRefused(t *testing.T) {
	grant := createOfflineGrant(t)
	idToken, _ := sessionBoundGrantOnSameSession(t, grant)

	hint, err := idtokenhint.Encrypt(idToken+"\n", grant.clientSecret)
	require.NoError(t, err)

	resp := logoutThroughConsentPage(t, grant.httpClient, url.Values{
		"id_token_hint":            {hint},
		"post_logout_redirect_uri": {grant.signOutRedirectURI},
		"client_id":                {grant.client.ClientIdentifier},
		"state":                    {fake.LetterN(8)},
	})
	defer func() { _ = resp.Body.Close() }()

	require.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Empty(t, resp.Header.Get("Location"), "a hint whose inner token is malformed earns no redirect")
	assertSignedOutPage(t, resp, signedOutEnglish, true)
}
