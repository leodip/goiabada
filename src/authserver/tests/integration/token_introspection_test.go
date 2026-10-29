package integration

import (
	"context"
	"database/sql"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/leodip/goiabada/authserver/internal/fake"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/builtin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Introspection at /auth/introspect (RFC 7662, #676 decisions 5, 7, 9 and 13). An API calls as a
// confidential client whose introspection resources an administrator listed, and learns whether a
// token is active. An access token is active only while the one access-token check passes and its
// aud names a resource on the caller's list; a refresh token only to its own client, while the
// refresh grant's check passes. Anything else is exactly {"active": false}. So introspection follows
// each of the five server-side revocations, a revocation through /auth/revoke and a disabled client
// at once, and an unlisted caller gets {"active": false} for a live token.

// introspectingAPI is a confidential client standing for an API, with its secret.
type introspectingAPI struct {
	client *record.Client
	secret string
}

// createIntrospectingAPI creates a confidential client whose introspection resources are the
// resources resourceIdentifiers name, deleted when the test ends.
func createIntrospectingAPI(t *testing.T, resourceIdentifiers ...string) introspectingAPI {
	t.Helper()
	secret := fake.Password(32)
	encrypted, err := dataCipher.Encrypt(secret)
	require.NoError(t, err)
	client := &record.Client{
		ClientIdentifier:      "introspecting-api-" + fake.LetterN(8),
		Enabled:               true,
		ClientSecretEncrypted: encrypted,
	}
	require.NoError(t, database.CreateClient(context.Background(), nil, client))
	t.Cleanup(func() { _ = database.DeleteClient(context.Background(), nil, client.Id) })
	for _, identifier := range resourceIdentifiers {
		resource, err := database.GetResourceByResourceIdentifier(context.Background(), nil, identifier)
		require.NoError(t, err)
		require.NotNil(t, resource, identifier)
		require.NoError(t, database.CreateClientIntrospectionResource(context.Background(), nil,
			&record.ClientIntrospectionResource{ClientId: client.Id, ResourceId: resource.Id}))
	}
	return introspectingAPI{client: client, secret: secret}
}

// authserverAPI is an introspecting client listing the authserver resource, which every sign-in
// token with openid names in aud.
func authserverAPI(t *testing.T) introspectingAPI {
	t.Helper()
	return createIntrospectingAPI(t, builtin.AuthServerResourceIdentifier)
}

// introspectRequest is one request to the introspection endpoint: the form, Basic credentials when
// basicUser is not empty, and header fields of its own.
type introspectRequest struct {
	method    string
	form      url.Values
	basicUser string
	basicPass string
	header    map[string]string
}

type introspectAnswer struct {
	status int
	header http.Header
	body   string
}

func postIntrospect(t *testing.T, request introspectRequest) introspectAnswer {
	t.Helper()
	method := request.method
	if method == "" {
		method = http.MethodPost
	}
	req, err := http.NewRequest(method, appConfig.AuthServer.BaseURL+"/auth/introspect",
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
	return introspectAnswer{status: resp.StatusCode, header: resp.Header, body: string(body)}
}

// introspectAs introspects token as the client, with Basic credentials, and returns the answer's
// members after requiring 200 and Cache-Control: no-store (RFC 7662 section 4).
func introspectAs(t *testing.T, clientIdentifier, clientSecret, token string) map[string]interface{} {
	t.Helper()
	answer := postIntrospect(t, introspectRequest{form: url.Values{"token": {token}},
		basicUser: clientIdentifier, basicPass: clientSecret})
	require.Equal(t, http.StatusOK, answer.status, answer.body)
	assert.Equal(t, "application/json", answer.header.Get("Content-Type"))
	assert.Equal(t, "no-store", answer.header.Get("Cache-Control"))
	var members map[string]interface{}
	require.NoError(t, json.Unmarshal([]byte(answer.body), &members), answer.body)
	return members
}

func (api introspectingAPI) introspect(t *testing.T, token string) map[string]interface{} {
	t.Helper()
	return introspectAs(t, api.client.ClientIdentifier, api.secret, token)
}

// assertActive asserts the answer is active.
func assertActive(t *testing.T, members map[string]interface{}) {
	t.Helper()
	assert.Equal(t, true, members["active"], "%v", members)
}

// assertInactive asserts the answer is exactly {"active": false}, saying nothing of why (RFC 7662
// section 2.2).
func assertInactive(t *testing.T, members map[string]interface{}) {
	t.Helper()
	assert.Equal(t, map[string]interface{}{"active": false}, members)
}

// An access token whose aud names a resource on the caller's list is active, answered with RFC 7662
// section 2.2's members read from the token and nothing else: the sign-in's other claims, the
// session and the grant stay out of it.
func TestIntrospect_AnAccessTokenIsActiveToAListedResource(t *testing.T) {
	resource := createResource(t)
	permission := createPermission(t, resource.Id)
	scope := "openid " + resource.ResourceIdentifier + ":" + permission.PermissionIdentifier
	data, code, _, _ := userTokenResponseWithScope(t, scope, nil)
	t.Cleanup(func() { _ = database.DeleteClient(context.Background(), nil, code.ClientId) })
	accessToken := data["access_token"].(string)
	claims := decodeJWTPayload(t, accessToken)
	api := createIntrospectingAPI(t, resource.ResourceIdentifier)

	members := api.introspect(t, accessToken)

	assert.Equal(t, map[string]interface{}{
		"active":     true,
		"scope":      scope,
		"client_id":  code.Client.ClientIdentifier,
		"sub":        code.User.Subject,
		"aud":        claims["aud"],
		"iss":        claims["iss"],
		"exp":        claims["exp"],
		"iat":        claims["iat"],
		"nbf":        claims["nbf"],
		"jti":        claims["jti"],
		"token_type": "Bearer",
	}, members)
	assert.ElementsMatch(t, []interface{}{resource.ResourceIdentifier, builtin.AuthServerResourceIdentifier}, claims["aud"])
}

// A caller not allowed for a token gets {"active": false} for a live one: a confidential client
// listing nothing, and one listing another resource. The token goes on working.
func TestIntrospect_AnUnlistedCallerGetsInactiveForALiveToken(t *testing.T) {
	resource := createResource(t)
	permission := createPermission(t, resource.Id)
	other := createResource(t)
	data, code, _, clientSecret := userTokenResponseWithScope(t, resource.ResourceIdentifier+":"+permission.PermissionIdentifier, nil)
	t.Cleanup(func() { _ = database.DeleteClient(context.Background(), nil, code.ClientId) })
	accessToken := data["access_token"].(string)
	require.Equal(t, resource.ResourceIdentifier, decodeJWTPayload(t, accessToken)["aud"])
	assertActive(t, createIntrospectingAPI(t, resource.ResourceIdentifier).introspect(t, accessToken))

	assertInactive(t, createIntrospectingAPI(t).introspect(t, accessToken))
	assertInactive(t, createIntrospectingAPI(t, other.ResourceIdentifier).introspect(t, accessToken))
	// The client the token was issued to is not on any list either.
	assertInactive(t, introspectAs(t, code.Client.ClientIdentifier, clientSecret, accessToken))
}

// A refresh token is answered to the client it was issued to (decision 7): active, with scope,
// client_id, sub, iss, exp, iat and jti, and no aud or token_type. Introspecting it spends nothing:
// it refreshes afterwards. Any other caller, even one listed for the authserver resource, gets
// {"active": false}.
func TestIntrospect_ARefreshTokenIsActiveToItsOwnClientAlone(t *testing.T) {
	data, code, httpClient, clientSecret := userTokenResponseWithScope(t, "openid", nil)
	t.Cleanup(func() { _ = database.DeleteClient(context.Background(), nil, code.ClientId) })
	refreshToken := data["refresh_token"].(string)
	claims := decodeJWTPayload(t, refreshToken)

	members := introspectAs(t, code.Client.ClientIdentifier, clientSecret, refreshToken)

	assert.Equal(t, map[string]interface{}{
		"active":    true,
		"scope":     "openid",
		"client_id": code.Client.ClientIdentifier,
		"sub":       code.User.Subject,
		"iss":       claims["iss"],
		"exp":       claims["exp"],
		"iat":       claims["iat"],
		"jti":       claims["jti"],
	}, members)
	assertInactive(t, authserverAPI(t).introspect(t, refreshToken))

	status, rotated := refreshAuthCodeGrant(t, httpClient, code, clientSecret, refreshToken, "")
	require.Equal(t, http.StatusOK, status, "introspection spent nothing: %v", rotated)

	// The token rotated out is inactive, and presenting it here is no replay: the grant lives on.
	assertInactive(t, introspectAs(t, code.Client.ClientIdentifier, clientSecret, refreshToken))
	assertActive(t, introspectAs(t, code.Client.ClientIdentifier, clientSecret, rotated["refresh_token"].(string)))
	status, again := refreshAuthCodeGrant(t, httpClient, code, clientSecret, rotated["refresh_token"].(string), "")
	assert.Equal(t, http.StatusOK, status, "%v", again)
}

// A credential change revokes the user's authentication state: the grant's access token and its
// refresh token are inactive.
func TestIntrospect_FollowsACredentialChange(t *testing.T) {
	api := authserverAPI(t)
	grant := createOfflineGrant(t)
	assertActive(t, api.introspect(t, grant.accessToken))
	assertActive(t, introspectAs(t, grant.client.ClientIdentifier, grant.clientSecret, grant.refreshToken))

	resetPasswordFor(t, grant.user, fake.Password(20))

	assertInactive(t, api.introspect(t, grant.accessToken))
	assertInactive(t, introspectAs(t, grant.client.ClientIdentifier, grant.clientSecret, grant.refreshToken))
}

// Ending the session an offline grant came from revokes the grant: its access token, which names no
// session, and its refresh token are inactive.
func TestIntrospect_FollowsASessionEnded(t *testing.T) {
	adminToken, _ := createAdminClientWithToken(t)
	api := authserverAPI(t)
	grant := createOfflineGrant(t)
	assertActive(t, api.introspect(t, grant.accessToken))

	session, err := database.GetUserSessionBySessionIdentifier(context.Background(), nil, grant.sessionIdentifier)
	require.NoError(t, err)
	require.NotNil(t, session)
	deleteThroughAdminAPI(t, adminToken, "/api/v1/admin/user-sessions/"+strconv.FormatInt(session.Id, 10))

	assertInactive(t, api.introspect(t, grant.accessToken))
	assertInactive(t, introspectAs(t, grant.client.ClientIdentifier, grant.clientSecret, grant.refreshToken))
}

// A redeemed code presented again revokes what it issued: the access token is inactive.
func TestIntrospect_FollowsACodeReused(t *testing.T) {
	api := authserverAPI(t)
	clientSecret := fake.LetterN(32)
	httpClient, code := createAuthCode(t, clientSecret, "openid profile email")
	t.Cleanup(func() { _ = database.DeleteClient(context.Background(), nil, code.ClientId) })
	first := redeemCode(t, httpClient, code, clientSecret)
	accessToken := first["access_token"].(string)
	assertActive(t, api.introspect(t, accessToken))

	form := url.Values{
		"grant_type": {"authorization_code"}, "client_id": {code.Client.ClientIdentifier},
		"client_secret": {clientSecret}, "code": {code.Code}, "redirect_uri": {code.RedirectURI},
		"code_verifier": {testCodeVerifier},
	}
	replayed := postToTokenEndpoint(t, httpClient, appConfig.AuthServer.BaseURL+"/auth/token/", form)
	require.Equal(t, "invalid_grant", replayed["error"], "%v", replayed)

	assertInactive(t, api.introspect(t, accessToken))
	assertInactive(t, introspectAs(t, code.Client.ClientIdentifier, clientSecret, first["refresh_token"].(string)))
}

// Making a client public revokes its grants: their access tokens are inactive, though the client
// stays enabled.
func TestIntrospect_FollowsAClientMadePublic(t *testing.T) {
	adminToken, _ := createAdminClientWithToken(t)
	api := authserverAPI(t)
	clientSecret := fake.LetterN(32)
	httpClient, code := createAuthCode(t, clientSecret, "openid profile email")
	t.Cleanup(func() { _ = database.DeleteClient(context.Background(), nil, code.ClientId) })
	accessToken := redeemCode(t, httpClient, code, clientSecret)["access_token"].(string)
	assertActive(t, api.introspect(t, accessToken))

	flipToPublic(t, adminToken, code.ClientId)

	assertInactive(t, api.introspect(t, accessToken))
}

// A user withdraws their consent to a client: the access tokens of their grants with it are inactive.
func TestIntrospect_FollowsConsentWithdrawn(t *testing.T) {
	adminToken, _ := createAdminClientWithToken(t)
	api := authserverAPI(t)
	data, code, _, _ := userTokenResponseWithScope(t, "openid", nil)
	t.Cleanup(func() { _ = database.DeleteClient(context.Background(), nil, code.ClientId) })
	accessToken := data["access_token"].(string)
	assertActive(t, api.introspect(t, accessToken))

	consent, err := database.GetConsentByUserIdAndClientId(context.Background(), nil, code.UserId, code.ClientId)
	require.NoError(t, err)
	if consent == nil {
		consent = &record.UserConsent{UserId: code.UserId, ClientId: code.ClientId, Scope: code.Scope,
			GrantedAt: sql.NullTime{Time: time.Now().UTC(), Valid: true}}
		require.NoError(t, database.CreateUserConsent(context.Background(), nil, consent))
	}
	deleteThroughAdminAPI(t, adminToken, "/api/v1/admin/user-consents/"+strconv.FormatInt(consent.Id, 10))

	assertInactive(t, api.introspect(t, accessToken))
}

// A revocation through /auth/revoke ends the grant: the access token issued with it is inactive at
// once, and so is the refresh token to its own client.
func TestIntrospect_FollowsARevocationOfTheGrant(t *testing.T) {
	api := authserverAPI(t)
	data, code, _, clientSecret := userTokenResponseWithScope(t, "openid", nil)
	t.Cleanup(func() { _ = database.DeleteClient(context.Background(), nil, code.ClientId) })
	accessToken := data["access_token"].(string)
	refreshToken := data["refresh_token"].(string)
	assertActive(t, api.introspect(t, accessToken))

	revokeAs(t, code.Client.ClientIdentifier, clientSecret, refreshToken)

	assertInactive(t, api.introspect(t, accessToken))
	assertInactive(t, introspectAs(t, code.Client.ClientIdentifier, clientSecret, refreshToken))
}

// A client credentials token revoked through /auth/revoke, which has no grant, is inactive at once:
// its jti is stored.
func TestIntrospect_FollowsARevocationOfAnAccessTokenWithoutAGrant(t *testing.T) {
	api := authserverAPI(t)
	accessToken, client, clientSecret := createAdminClientWithTokenAndSecret(t)
	t.Cleanup(func() { _ = database.DeleteClient(context.Background(), nil, client.Id) })
	require.NotContains(t, decodeJWTPayload(t, accessToken), "grant_id")
	members := api.introspect(t, accessToken)
	assertActive(t, members)
	assert.Equal(t, client.ClientIdentifier, members["sub"], "a client credentials token's subject is its client")

	revokeAs(t, client.ClientIdentifier, clientSecret, accessToken)

	assertInactive(t, api.introspect(t, accessToken))
}

// A disabled client's access tokens are inactive while it stays disabled, and active again once it
// is re-enabled before they expire (decision 6).
func TestIntrospect_FollowsADisabledClient(t *testing.T) {
	api := authserverAPI(t)
	data, code, _, _ := userTokenResponseWithScope(t, "openid", nil)
	t.Cleanup(func() { _ = database.DeleteClient(context.Background(), nil, code.ClientId) })
	accessToken := data["access_token"].(string)
	assertActive(t, api.introspect(t, accessToken))

	client, err := database.GetClientById(context.Background(), nil, code.ClientId)
	require.NoError(t, err)
	client.Enabled = false
	require.NoError(t, database.UpdateClient(context.Background(), nil, client))

	assertInactive(t, api.introspect(t, accessToken))

	client.Enabled = true
	require.NoError(t, database.UpdateClient(context.Background(), nil, client))
	assertActive(t, api.introspect(t, accessToken))
}

// An invalid token is inactive: a string that is no token, a token signed by no key and an ID token.
func TestIntrospect_AnInvalidTokenIsInactive(t *testing.T) {
	api := authserverAPI(t)
	data, code, _, _ := userTokenResponseWithScope(t, "openid", nil)
	t.Cleanup(func() { _ = database.DeleteClient(context.Background(), nil, code.ClientId) })

	for name, token := range map[string]string{
		"a string that is no token": "not-a-token",
		"a token signed by no key":  forgedToken(t, data["access_token"].(string)),
		"an ID token":               data["id_token"].(string),
	} {
		t.Run(name, func(t *testing.T) {
			assertInactive(t, api.introspect(t, token))
		})
	}
}

// A caller authenticates, and a public client cannot (RFC 7662 section 4): 401 invalid_client with
// the Basic challenge for a wrong secret and for a public client, before the token is read.
func TestIntrospect_TheCallerAuthenticates(t *testing.T) {
	api := authserverAPI(t)
	data, code, _, _ := userTokenResponseWithScope(t, "openid", nil)
	t.Cleanup(func() { _ = database.DeleteClient(context.Background(), nil, code.ClientId) })
	accessToken := data["access_token"].(string)

	answer := postIntrospect(t, introspectRequest{form: url.Values{"token": {accessToken}},
		basicUser: api.client.ClientIdentifier, basicPass: "not-the-secret"})
	assertIntrospectError(t, answer, http.StatusUnauthorized, "invalid_client",
		"Client authentication failed. Please review your client_secret.")
	assert.Equal(t, `Basic realm="goiabada"`, answer.header.Get("WWW-Authenticate"))

	public := &record.Client{ClientIdentifier: "public-introspector-" + fake.LetterN(8), Enabled: true, IsPublic: true}
	require.NoError(t, database.CreateClient(context.Background(), nil, public))
	t.Cleanup(func() { _ = database.DeleteClient(context.Background(), nil, public.Id) })
	answer = postIntrospect(t, introspectRequest{form: url.Values{"token": {accessToken}, "client_id": {public.ClientIdentifier}}})
	assertIntrospectError(t, answer, http.StatusUnauthorized, "invalid_client",
		"This client is configured as public, and a public client cannot introspect tokens. Introspect as a confidential client.")
	assert.Equal(t, `Basic realm="goiabada"`, answer.header.Get("WWW-Authenticate"))
	assert.Equal(t, "no-store", answer.header.Get("Cache-Control"))
}

// assertIntrospectError asserts answer is an RFC 6749 section 5.2 error with status, code and
// description.
func assertIntrospectError(t *testing.T, answer introspectAnswer, status int, code, description string) {
	t.Helper()
	require.Equal(t, status, answer.status, answer.body)
	var body map[string]string
	require.NoError(t, json.Unmarshal([]byte(answer.body), &body), answer.body)
	assert.Equal(t, map[string]string{"error": code, "error_description": description}, body)
}

// GET is refused (RFC 7662 section 4 MAY), so no token reaches a URL.
func TestIntrospect_RefusesGet(t *testing.T) {
	answer := postIntrospect(t, introspectRequest{method: http.MethodGet})

	assert.Equal(t, http.StatusMethodNotAllowed, answer.status, answer.body)
	assert.Equal(t, "POST", answer.header.Get("Allow"))
}

// The endpoint is exempt from the CSRF check, as an API calls it from wherever it runs, and answers
// no CORS: a public client, the only kind a browser holds, never introspects.
func TestIntrospect_IsExemptFromCSRFAndAnswersNoCORS(t *testing.T) {
	api := authserverAPI(t)
	data, code, _, _ := userTokenResponseWithScope(t, "openid", nil)
	t.Cleanup(func() { _ = database.DeleteClient(context.Background(), nil, code.ClientId) })
	registered := "https://introspect-" + strings.ToLower(fake.LetterN(8)) + ".example.com"
	require.NoError(t, database.CreateWebOrigin(context.Background(), nil, &record.WebOrigin{
		ClientId: code.ClientId, Origin: registered,
	}))

	answer := postIntrospect(t, introspectRequest{
		form:      url.Values{"token": {data["access_token"].(string)}},
		basicUser: api.client.ClientIdentifier, basicPass: api.secret,
		header: map[string]string{"Origin": registered, "Sec-Fetch-Site": "cross-site"},
	})

	require.Equal(t, http.StatusOK, answer.status, "not refused by the CSRF check: %s", answer.body)
	assert.Contains(t, answer.body, `"active":true`)
	assert.Empty(t, answer.header.Get("Access-Control-Allow-Origin"), "a registered web origin is not named")
}

// Discovery announces the endpoint and the client authentication methods it accepts (RFC 8414
// section 2), at both addresses: none is not among them.
func TestIntrospect_IsAnnouncedInDiscovery(t *testing.T) {
	for _, path := range []string{"/.well-known/openid-configuration", "/.well-known/oauth-authorization-server"} {
		t.Run(path, func(t *testing.T) {
			resp, body := fetchDiscoveryAt(t, path, "")
			require.Equal(t, http.StatusOK, resp.StatusCode)
			var document struct {
				IntrospectionEndpoint string   `json:"introspection_endpoint"`
				AuthMethods           []string `json:"introspection_endpoint_auth_methods_supported"`
			}
			require.NoError(t, json.Unmarshal(body, &document))

			assert.Equal(t, appConfig.AuthServer.BaseURL+"/auth/introspect", document.IntrospectionEndpoint)
			assert.ElementsMatch(t, []string{"client_secret_basic", "client_secret_post"}, document.AuthMethods)
		})
	}
}
