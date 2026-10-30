package integration

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/leodip/goiabada/authserver/internal/audit"
	"github.com/leodip/goiabada/authserver/internal/fake"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Revocation at /auth/revoke (RFC 7009, #676 decisions 1, 8, 9, 10 and 12). A client sends its
// refresh token or an access token carrying grant_id, and the whole grant ends at once: the refresh
// token is refused at the token endpoint, every token of its family with it, and every access token
// of the grant at /userinfo. Another client's live token is refused with 400 invalid_grant and stays
// live; an invalid token is answered 200 with an empty body; the hint is ignored. The endpoint answers
// CORS for registered web origins, is exempt from the CSRF check and is announced in discovery.

// revokeRequest is one request to the revocation endpoint: the form, and Basic credentials when
// basicUser is not empty, and header fields of its own.
type revokeRequest struct {
	form      url.Values
	basicUser string
	basicPass string
	header    map[string]string
}

// revokeAnswer is what the endpoint answered.
type revokeAnswer struct {
	status int
	header http.Header
	body   string
}

func postRevoke(t *testing.T, request revokeRequest) revokeAnswer {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, appConfig.AuthServer.BaseURL+"/auth/revoke",
		strings.NewReader(request.form.Encode()))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if request.basicUser != "" {
		req.SetBasicAuth(url.QueryEscape(request.basicUser), url.QueryEscape(request.basicPass))
	}
	for name, value := range request.header {
		req.Header.Set(name, value)
	}
	resp, err := createHttpClient(t).Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	return revokeAnswer{status: resp.StatusCode, header: resp.Header, body: string(body)}
}

// revokeAs revokes token as the confidential client, in the body, and requires 200 with an empty
// body, RFC 7009 section 2.2's answer for a token revoked and for an invalid one alike.
func revokeAs(t *testing.T, clientIdentifier, clientSecret, token string) {
	t.Helper()
	answer := postRevoke(t, revokeRequest{form: url.Values{
		"token": {token}, "client_id": {clientIdentifier}, "client_secret": {clientSecret},
	}})
	require.Equal(t, http.StatusOK, answer.status, answer.body)
	assert.Empty(t, answer.body, "RFC 7009 section 2.2: the content of the response body is ignored")
}

// assertRevokeError asserts answer is an RFC 6749 section 5.2 error with status, code and
// description.
func assertRevokeError(t *testing.T, answer revokeAnswer, status int, code, description string) {
	t.Helper()
	require.Equal(t, status, answer.status, answer.body)
	var body map[string]string
	require.NoError(t, json.Unmarshal([]byte(answer.body), &body), answer.body)
	assert.Equal(t, map[string]string{"error": code, "error_description": description}, body)
}

// assertRevokedRefreshRefused asserts the token endpoint refuses refreshToken with invalid_grant.
func assertRevokedRefreshRefused(t *testing.T, clientIdentifier, clientSecret, refreshToken string) {
	t.Helper()
	status, body := refreshWithScope(t, createHttpClient(t), clientIdentifier, clientSecret, refreshToken, "")
	require.Equal(t, http.StatusBadRequest, status, "%v", body)
	assert.Equal(t, "invalid_grant", body["error"])
}

// A refresh token revoked at the endpoint ends its whole grant: the token itself is refused at the
// token endpoint, and so is every access token of its family at /userinfo, the one issued before the
// rotation included. Revoking it again is answered as any invalid token is.
func TestRevoke_ARefreshTokenEndsItsWholeGrant(t *testing.T) {
	data, code, httpClient, clientSecret := userTokenResponseWithScope(t, "openid", nil)
	firstAccess := data["access_token"].(string)
	status, rotated := refreshAuthCodeGrant(t, httpClient, code, clientSecret, data["refresh_token"].(string), "")
	require.Equal(t, http.StatusOK, status, "%v", rotated)
	latestAccess := rotated["access_token"].(string)
	latestRefresh := rotated["refresh_token"].(string)
	assertUserinfoAdmits(t, latestAccess, code.User.Subject)

	answer := postRevoke(t, revokeRequest{
		form:      url.Values{"token": {latestRefresh}},
		basicUser: code.Client.ClientIdentifier, basicPass: clientSecret,
	})
	require.Equal(t, http.StatusOK, answer.status, answer.body)
	assert.Empty(t, answer.body)

	assertRevokedRefreshRefused(t, code.Client.ClientIdentifier, clientSecret, latestRefresh)
	assertUserinfoRefusesTheToken(t, firstAccess)
	assertUserinfoRefusesTheToken(t, latestAccess)

	revokeAs(t, code.Client.ClientIdentifier, clientSecret, latestRefresh)
}

// An access token carrying grant_id ends its grant, refresh token included: a library that revokes
// the access token first and then the refresh token, as oidc-client-ts does, gets 200 for both. The
// access token issued before a rotation ends the refresh token issued after it.
func TestRevoke_AnAccessTokenEndsItsGrant(t *testing.T) {
	data, code, httpClient, clientSecret := userTokenResponseWithScope(t, "openid", nil)
	firstAccess := data["access_token"].(string)
	require.Contains(t, decodeJWTPayload(t, firstAccess), "grant_id")
	status, rotated := refreshAuthCodeGrant(t, httpClient, code, clientSecret, data["refresh_token"].(string), "")
	require.Equal(t, http.StatusOK, status, "%v", rotated)
	latestRefresh := rotated["refresh_token"].(string)
	latestAccess := rotated["access_token"].(string)

	revokeAs(t, code.Client.ClientIdentifier, clientSecret, firstAccess)

	assertRevokedRefreshRefused(t, code.Client.ClientIdentifier, clientSecret, latestRefresh)
	assertUserinfoRefusesTheToken(t, firstAccess)
	assertUserinfoRefusesTheToken(t, latestAccess)

	revokeAs(t, code.Client.ClientIdentifier, clientSecret, latestRefresh)
}

// Revoking a grant ends that grant and nothing else: the user's grant with another client, held in
// the same browser session, goes on working.
func TestRevoke_EndsOneGrantAndNothingElse(t *testing.T) {
	data, code, _, clientSecret := userTokenResponseWithScope(t, "openid", nil)

	otherSecret := fake.LetterN(32)
	password := fake.Password(12)
	user, err := database.GetUserById(context.Background(), nil, code.UserId)
	require.NoError(t, err)
	setUserPassword(t, user, password)
	otherHttpClient, otherCode := createAuthCode(t, otherSecret, "openid",
		authCodeOptions{user: user, userPassword: password})
	t.Cleanup(func() { _ = database.DeleteClient(context.Background(), nil, otherCode.ClientId) })
	other := redeemCode(t, otherHttpClient, otherCode, otherSecret)

	revokeAs(t, code.Client.ClientIdentifier, clientSecret, data["refresh_token"].(string))

	assertUserinfoRefusesTheToken(t, data["access_token"].(string))
	assertUserinfoAdmits(t, other["access_token"].(string), user.Subject)
	status, body := refreshWithScope(t, otherHttpClient, otherCode.Client.ClientIdentifier, otherSecret,
		other["refresh_token"].(string), "")
	assert.Equal(t, http.StatusOK, status, "the other client's grant is untouched: %v", body)
}

// A public client revokes with its client_id alone (RFC 7009 section 5), as a browser app does at
// sign-out.
func TestRevoke_APublicClientRevokesWithItsIdentifierAlone(t *testing.T) {
	enableROPCGlobally(t)
	password := fake.Password(12)
	client := createROPCClient(t, "", true)
	user := createROPCUser(t, password)
	data := postToTokenEndpoint(t, createHttpClient(t), appConfig.AuthServer.BaseURL+"/auth/token/", url.Values{
		"grant_type": {"password"}, "client_id": {client.ClientIdentifier},
		"username": {user.Email}, "password": {password}, "scope": {"openid"},
	})
	refreshToken := data["refresh_token"].(string)
	require.NotEmpty(t, refreshToken, "%v", data)

	answer := postRevoke(t, revokeRequest{form: url.Values{"token": {refreshToken}, "client_id": {client.ClientIdentifier}}})

	require.Equal(t, http.StatusOK, answer.status, answer.body)
	assert.Empty(t, answer.body)
	refused := presentRefreshToken(t, client.ClientIdentifier, refreshToken, "")
	assert.Equal(t, "invalid_grant", refused["error"], "%v", refused)
	assertUserinfoRefusesTheToken(t, data["access_token"].(string))
}

// A client that sends another client's live token is refused with 400 invalid_grant (decision 8),
// and nothing is revoked: the token goes on working for the client it was issued to.
func TestRevoke_AnotherClientsLiveTokenIsRefused(t *testing.T) {
	data, code, httpClient, clientSecret := userTokenResponseWithScope(t, "openid", nil)
	otherSecret := fake.LetterN(32)
	_, otherCode := createAuthCode(t, otherSecret, "openid")
	t.Cleanup(func() { _ = database.DeleteClient(context.Background(), nil, otherCode.ClientId) })

	for name, token := range map[string]string{
		"a refresh token": data["refresh_token"].(string),
		"an access token": data["access_token"].(string),
	} {
		t.Run(name, func(t *testing.T) {
			answer := postRevoke(t, revokeRequest{form: url.Values{
				"token": {token}, "client_id": {otherCode.Client.ClientIdentifier}, "client_secret": {otherSecret},
			}})

			assertRevokeError(t, answer, http.StatusBadRequest, "invalid_grant", "The token was issued to another client.")
		})
	}

	assertUserinfoAdmits(t, data["access_token"].(string), code.User.Subject)
	status, refreshed := refreshAuthCodeGrant(t, httpClient, code, clientSecret, data["refresh_token"].(string), "")
	assert.Equal(t, http.StatusOK, status, "the grant is untouched: %v", refreshed)
}

// Replaying live tokens under different public client identifiers must not persist an event per
// request. The first refusal is still observable, and the token's owner can still revoke its grant.
func TestRevoke_RepeatedForeignTokensBoundAuditWrites(t *testing.T) {
	enableAuditLogsInDatabase(t)
	data, code, _, clientSecret := userTokenResponseWithScope(t, "openid", nil)
	callers := []*record.Client{createPublicClient(t), createPublicClient(t)}
	for _, caller := range callers {
		t.Cleanup(func() { _ = database.DeleteClient(context.Background(), nil, caller.Id) })
	}
	countEvents := func() int {
		t.Helper()
		_, count, err := database.GetAuditLogsPaginated(context.Background(), nil, 1, 1,
			audit.EventTokenRevocationRefused, "")
		require.NoError(t, err)
		return count
	}
	before := countEvents()
	started := time.Now()
	tokens := []string{data["access_token"].(string), data["refresh_token"].(string)}
	for i := range 12 {
		answer := postRevoke(t, revokeRequest{
			form: url.Values{
				"client_id": {callers[i%2].ClientIdentifier}, "token": {tokens[(i/2)%2]},
				"token_type_hint": {fake.LetterN(8)},
			},
			header: map[string]string{"X-Request-Id": fake.LetterN(16)},
		})
		assertRevokeError(t, answer, http.StatusBadRequest, "invalid_grant", "The token was issued to another client.")
	}
	// The running server's fixed window can roll during the burst. Allow that boundary and any
	// full minutes elapsed, without depending on the instant the server constructed its gate.
	maxEvents := 2 + int(time.Since(started)/time.Minute)
	written := countEvents() - before
	assert.GreaterOrEqual(t, written, 1, "the first refusal must be audited")
	assert.LessOrEqual(t, written, maxEvents, "replays must share the token owner's audit budget")

	assertUserinfoAdmits(t, tokens[0], code.User.Subject)
	revokeAs(t, code.Client.ClientIdentifier, clientSecret, tokens[1])
	assertUserinfoRefusesTheToken(t, tokens[0])
	assertRevokedRefreshRefused(t, code.Client.ClientIdentifier, clientSecret, tokens[1])
}

// An invalid token is answered 200 with an empty body, whatever it is (RFC 7009 section 2.2): one that
// does not parse, an ID token, and a refresh token already rotated. Nothing is revoked: the grant
// goes on working.
func TestRevoke_AnInvalidTokenIsAnsweredOK(t *testing.T) {
	data, code, httpClient, clientSecret := userTokenResponseWithScope(t, "openid", nil)
	status, rotated := refreshAuthCodeGrant(t, httpClient, code, clientSecret, data["refresh_token"].(string), "")
	require.Equal(t, http.StatusOK, status, "%v", rotated)

	for name, token := range map[string]string{
		"a string that is no token":   "not-a-token",
		"a token signed by no key":    forgedToken(t, data["access_token"].(string)),
		"an ID token":                 data["id_token"].(string),
		"a refresh token rotated out": data["refresh_token"].(string),
	} {
		t.Run(name, func(t *testing.T) {
			revokeAs(t, code.Client.ClientIdentifier, clientSecret, token)
		})
	}

	assertUserinfoAdmits(t, rotated["access_token"].(string), code.User.Subject)
	status, refreshed := refreshAuthCodeGrant(t, httpClient, code, clientSecret, rotated["refresh_token"].(string), "")
	assert.Equal(t, http.StatusOK, status, "the grant is untouched: %v", refreshed)
}

// forgedToken is token with its signature replaced, so no key verifies it.
func forgedToken(t *testing.T, token string) string {
	t.Helper()
	parts := strings.Split(token, ".")
	require.Len(t, parts, 3)
	return parts[0] + "." + parts[1] + "." + strings.Repeat("A", len(parts[2]))
}

// token_type_hint is ignored: a refresh token sent with the access-token hint, or an unknown one, is
// revoked all the same (RFC 7009 section 2.1).
func TestRevoke_TheHintIsIgnored(t *testing.T) {
	for _, hint := range []string{"access_token", "no_such_hint"} {
		t.Run(hint, func(t *testing.T) {
			data, code, _, clientSecret := userTokenResponseWithScope(t, "openid", nil)
			refreshToken := data["refresh_token"].(string)

			answer := postRevoke(t, revokeRequest{form: url.Values{
				"token": {refreshToken}, "token_type_hint": {hint},
				"client_id": {code.Client.ClientIdentifier}, "client_secret": {clientSecret},
			}})

			require.Equal(t, http.StatusOK, answer.status, answer.body)
			assertRevokedRefreshRefused(t, code.Client.ClientIdentifier, clientSecret, refreshToken)
		})
	}
}

// The client authenticates as at the token endpoint, before the token is read: a wrong secret is
// 401 invalid_client with the Basic challenge, and the token is left live. A request without a token
// is 400 invalid_request.
func TestRevoke_TheClientAuthenticates(t *testing.T) {
	data, code, _, clientSecret := userTokenResponseWithScope(t, "openid", nil)
	refreshToken := data["refresh_token"].(string)

	answer := postRevoke(t, revokeRequest{
		form:      url.Values{"token": {refreshToken}},
		basicUser: code.Client.ClientIdentifier, basicPass: "not-the-secret",
	})
	assertRevokeError(t, answer, http.StatusUnauthorized, "invalid_client",
		"Client authentication failed. Please review your client_secret.")
	assert.Equal(t, `Basic realm="goiabada"`, answer.header.Get("WWW-Authenticate"))

	answer = postRevoke(t, revokeRequest{form: url.Values{
		"client_id": {code.Client.ClientIdentifier}, "client_secret": {clientSecret},
	}})
	assertRevokeError(t, answer, http.StatusBadRequest, "invalid_request", "Missing required token parameter.")

	assertUserinfoAdmits(t, data["access_token"].(string), code.User.Subject)
}

// An access token without a grant, of the client credentials grant, is revoked by its own jti (#676
// decision 1): the admin API refuses it at once, though it has not expired, and revoking it again is
// answered as any invalid token is. Before that, another client's attempt to revoke it is refused and
// leaves it working.
func TestRevoke_AClientCredentialsTokenIsRevokedByItsJti(t *testing.T) {
	accessToken, client, clientSecret := createAdminClientWithTokenAndSecret(t)
	t.Cleanup(func() { _ = database.DeleteClient(context.Background(), nil, client.Id) })
	claims := decodeJWTPayload(t, accessToken)
	require.NotContains(t, claims, "grant_id", "a client credentials token has no grant")
	jti := claims["jti"].(string)
	const target = "/api/v1/admin/resources"
	assertAPIAdmitsToken(t, target, accessToken)

	_, other, otherSecret := createAdminClientWithTokenAndSecret(t)
	t.Cleanup(func() { _ = database.DeleteClient(context.Background(), nil, other.Id) })
	answer := postRevoke(t, revokeRequest{form: url.Values{
		"token": {accessToken}, "client_id": {other.ClientIdentifier}, "client_secret": {otherSecret},
	}})
	assertRevokeError(t, answer, http.StatusBadRequest, "invalid_grant", "The token was issued to another client.")
	assertAPIAdmitsToken(t, target, accessToken)

	revokeAs(t, client.ClientIdentifier, clientSecret, accessToken)

	assertAPIRefusesToken(t, target, accessToken)
	revoked, err := database.IsAccessTokenRevoked(context.Background(), nil, jti)
	require.NoError(t, err)
	assert.True(t, revoked, "the token's jti is stored")

	revokeAs(t, client.ClientIdentifier, clientSecret, accessToken)
	assertAPIRefusesToken(t, target, accessToken)
}

// An access token of the implicit flow, which has no grant either, is revoked by its jti, by a
// public client with its client_id alone as a browser app does at sign-out: /userinfo refuses it at
// once.
func TestRevoke_AnImplicitFlowTokenIsRevokedByItsJti(t *testing.T) {
	enableImplicitFlowGlobally(t)
	implicitEnabled := true
	client, redirectUri := createImplicitFlowClient(t, &implicitEnabled)
	client.IsPublic = true
	require.NoError(t, database.UpdateClient(context.Background(), nil, client))
	t.Cleanup(func() { _ = database.DeleteClient(context.Background(), nil, client.Id) })
	user, password := createTestUserForImplicit(t)
	resp := signInToIssue(t, createHttpClient(t),
		implicitModeAuthorizeURL(client, redirectUri.URI, "token", "", fake.LetterN(12), ""), user, password)
	_ = resp.Body.Close()
	require.Equal(t, http.StatusFound, resp.StatusCode)
	accessToken := getTokensFromFragment(t, resp)["access_token"]
	require.NotEmpty(t, accessToken)
	require.NotContains(t, decodeJWTPayload(t, accessToken), "grant_id", "an implicit-flow token has no grant")
	assertUserinfoAdmits(t, accessToken, user.Subject)

	answer := postRevoke(t, revokeRequest{form: url.Values{"token": {accessToken}, "client_id": {client.ClientIdentifier}}})

	require.Equal(t, http.StatusOK, answer.status, answer.body)
	assert.Empty(t, answer.body)
	assertUserinfoRefusesTheToken(t, accessToken)
}

// Discovery announces the endpoint and the client authentication methods it accepts (RFC 8414
// section 2), at both addresses.
func TestRevoke_IsAnnouncedInDiscovery(t *testing.T) {
	for _, path := range []string{"/.well-known/openid-configuration", "/.well-known/oauth-authorization-server"} {
		t.Run(path, func(t *testing.T) {
			resp, body := fetchDiscoveryAt(t, path, "")
			require.Equal(t, http.StatusOK, resp.StatusCode)
			var document struct {
				RevocationEndpoint string   `json:"revocation_endpoint"`
				AuthMethods        []string `json:"revocation_endpoint_auth_methods_supported"`
			}
			require.NoError(t, json.Unmarshal(body, &document))

			assert.Equal(t, appConfig.AuthServer.BaseURL+"/auth/revoke", document.RevocationEndpoint)
			assert.ElementsMatch(t, []string{"client_secret_basic", "client_secret_post", "none"}, document.AuthMethods)
		})
	}
}

// A browser app revokes at sign-out from its own origin: a cross-site POST is not refused by the
// CSRF check, and a registered web origin is named in Access-Control-Allow-Origin, on the preflight
// and on the request. An origin no client registered is not named.
func TestRevoke_AnswersCORSForRegisteredOriginsAndIsExemptFromCSRF(t *testing.T) {
	data, code, _, clientSecret := userTokenResponseWithScope(t, "openid", nil)
	registered := "https://revoke-" + strings.ToLower(fake.LetterN(8)) + ".example.com"
	unregistered := "https://revoke-" + strings.ToLower(fake.LetterN(8)) + ".example.com"
	require.NoError(t, database.CreateWebOrigin(context.Background(), nil, &record.WebOrigin{
		ClientId: code.ClientId, Origin: registered,
	}))

	req, err := http.NewRequest(http.MethodOptions, appConfig.AuthServer.BaseURL+"/auth/revoke", nil)
	require.NoError(t, err)
	req.Header.Set("Origin", registered)
	req.Header.Set("Access-Control-Request-Method", "POST")
	req.Header.Set("Access-Control-Request-Headers", "content-type")
	resp, err := createHttpClient(t).Do(req)
	require.NoError(t, err)
	_ = resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, registered, resp.Header.Get("Access-Control-Allow-Origin"), "the preflight is granted")
	assert.Equal(t, "POST", resp.Header.Get("Access-Control-Allow-Methods"))

	form := url.Values{"token": {data["access_token"].(string)}, "client_id": {code.Client.ClientIdentifier},
		"client_secret": {clientSecret}}

	answer := postRevoke(t, revokeRequest{form: form,
		header: map[string]string{"Origin": unregistered, "Sec-Fetch-Site": "cross-site"}})
	require.Equal(t, http.StatusOK, answer.status, "not refused by the CSRF check: %s", answer.body)
	assert.Empty(t, answer.header.Get("Access-Control-Allow-Origin"), "an unregistered origin is not named")

	answer = postRevoke(t, revokeRequest{form: form,
		header: map[string]string{"Origin": registered, "Sec-Fetch-Site": "cross-site"}})
	require.Equal(t, http.StatusOK, answer.status, answer.body)
	assert.Equal(t, registered, answer.header.Get("Access-Control-Allow-Origin"))

	assertUserinfoRefusesTheToken(t, data["access_token"].(string))
}
