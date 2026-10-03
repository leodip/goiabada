package integration

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/fake"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/builtin"
	"github.com/leodip/goiabada/core/oauth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The bearer path admits only an access token issued for authserver (#401). Every token this server
// signs verifies against the same key, so before this a refresh token or an ID token presented as a
// bearer credential got as far as each route's own checks, and a refresh token whose scope carried a
// route's permission passed that route's scope check. Now JwtAuthorizationHeaderToContext requires
// typ Bearer and an aud naming authserver, and a token failing either is answered exactly as one
// that does not parse.

// bearerKindGrant is the grant every non-access token below carries: a scope that passes the scope
// check of each of the four bearer-guarded groups, so nothing but the token's kind can stop it.
var bearerKindGrant = "openid " +
	builtin.AuthServerResourceIdentifier + ":" + builtin.ManageAccountPermissionIdentifier + " " +
	builtin.AuthServerResourceIdentifier + ":" + builtin.ManagePermissionIdentifier + " " +
	builtin.AuthServerResourceIdentifier + ":" + builtin.BrowserSessionsPermissionIdentifier

// bearerKindResponse is what a bearer-guarded route answered: the three things a caller can
// observe of a refusal.
type bearerKindResponse struct {
	status          int
	wwwAuthenticate string
	body            string
}

// bearerRoute is one route of one of the four bearer-guarded groups. form sends the token as the
// access_token form parameter, OIDC Core 1.0 section 5.3.1's second method, instead of the
// Authorization header.
type bearerRoute struct {
	name   string
	method string
	path   string
	body   interface{}
	form   bool
}

func bearerKindRoutes() []bearerRoute {
	return []bearerRoute{
		{name: "GET /userinfo", method: "GET", path: "/userinfo"},
		{name: "POST /userinfo, form body", method: "POST", path: "/userinfo", form: true},
		{name: "admin GET /api/v1/admin/settings/general", method: "GET", path: "/api/v1/admin/settings/general"},
		{name: "account PUT /api/v1/account/email", method: "PUT", path: "/api/v1/account/email",
			body: api.UpdateAccountEmailRequest{Email: "bearer-kind-" + strings.ToLower(fake.LetterN(8)) + "@attacker.example.com"}},
		{name: "browser-sessions POST /api/v1/sessions/load", method: "POST", path: "/api/v1/sessions/load",
			body: api.SessionLoadRequest{Id: strings.Repeat("ab", 32)}},
	}
}

// sendBearer presents a token to a route and returns what the caller sees.
func sendBearer(t *testing.T, route bearerRoute, token string) bearerKindResponse {
	t.Helper()

	var resp *http.Response
	if route.form {
		req, err := http.NewRequest(route.method, appConfig.AuthServer.BaseURL+route.path,
			strings.NewReader(url.Values{"access_token": {token}}.Encode()))
		require.NoError(t, err)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		resp, err = createHttpClient(t).Do(req)
		require.NoError(t, err)
	} else {
		resp = makeAPIRequest(t, route.method, appConfig.AuthServer.BaseURL+route.path, token, route.body)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	return bearerKindResponse{
		status:          resp.StatusCode,
		wwwAuthenticate: resp.Header.Get("WWW-Authenticate"),
		body:            string(body),
	}
}

// grantAuthServerPermissionsToUser grants a user the named authserver built-ins.
func grantAuthServerPermissionsToUser(t *testing.T, user *record.User, identifiers ...string) {
	t.Helper()

	resource, err := database.GetResourceByResourceIdentifier(context.Background(), nil, builtin.AuthServerResourceIdentifier)
	require.NoError(t, err)
	permissions, err := database.GetPermissionsByResourceId(context.Background(), nil, resource.Id)
	require.NoError(t, err)
	for _, identifier := range identifiers {
		granted := false
		for i := range permissions {
			if permissions[i].PermissionIdentifier == identifier {
				assignPermissionToUser(t, user.Id, permissions[i].Id)
				granted = true
				break
			}
		}
		require.True(t, granted, "built-in %q must exist", identifier)
	}
}

// TestBearerToken_NonAccessTokensAreRefusedAtEveryGroup: a session refresh token, an offline refresh
// token and an ID token, each validly signed by this server and each carrying or naming the user,
// answer 401 at /userinfo (both registrations), an admin route, an account route and a
// browser-sessions route, with the response a token that does not parse gets. The account route is
// a write, and the user's email is read back to show the handler never ran.
func TestBearerToken_NonAccessTokensAreRefusedAtEveryGroup(t *testing.T) {
	// The auth-code exchange yields the session refresh token and the ID token. No offline_access,
	// so the refresh token is typ Refresh.
	authCodeTokens, code, _, _ := userTokenResponseWithScope(t, bearerKindGrant, nil)
	sessionRefreshToken, ok := authCodeTokens["refresh_token"].(string)
	require.True(t, ok, "the exchange should yield a refresh token: %v", authCodeTokens)
	idToken, ok := authCodeTokens["id_token"].(string)
	require.True(t, ok, "the exchange should yield an ID token: %v", authCodeTokens)

	// ROPC's refresh token is always typ Offline.
	ropcTokens, ropcUser := ropcTokenResponse(t, bearerKindGrant, func(user *record.User) {
		grantAuthServerPermissionsToUser(t, user,
			builtin.ManageAccountPermissionIdentifier,
			builtin.ManagePermissionIdentifier,
			builtin.BrowserSessionsPermissionIdentifier)
	})
	offlineRefreshToken, ok := ropcTokens["refresh_token"].(string)
	require.True(t, ok, "ROPC should yield a refresh token: %v", ropcTokens)

	// The fixtures are what they are said to be, so a pass below is about the kind of token and
	// not a token that was never one of these.
	requireCarriesTheGrant := func(t *testing.T, token string) {
		t.Helper()
		scope, _ := decodeJWTPayload(t, token)["scope"].(string)
		require.ElementsMatch(t, strings.Fields(bearerKindGrant), strings.Fields(scope),
			"the refresh token's scope passes every group's scope check")
	}
	require.Equal(t, "Refresh", decodeJWTPayload(t, sessionRefreshToken)["typ"])
	requireCarriesTheGrant(t, sessionRefreshToken)
	require.Equal(t, "Offline", decodeJWTPayload(t, offlineRefreshToken)["typ"])
	requireCarriesTheGrant(t, offlineRefreshToken)
	idClaims := decodeJWTPayload(t, idToken)
	require.Nil(t, idClaims["typ"], "an ID token carries no typ")
	require.Equal(t, code.User.Subject, idClaims["sub"])

	tokens := []struct {
		name  string
		token string
		user  *record.User
	}{
		{name: "session refresh token", token: sessionRefreshToken, user: &code.User},
		{name: "offline refresh token", token: offlineRefreshToken, user: ropcUser},
		{name: "ID token", token: idToken, user: &code.User},
	}

	for _, route := range bearerKindRoutes() {
		unparseable := sendBearer(t, route, "not-a-jwt")
		require.Equal(t, http.StatusUnauthorized, unparseable.status, "%s: the baseline is a 401", route.name)
		require.Equal(t, `Bearer realm="goiabada", error="invalid_token", error_description="The access token is invalid."`,
			unparseable.wwwAuthenticate)
		// A presented token that is refused is invalid_token, never read as a missing one, in each
		// surface's own body (#435).
		if strings.HasPrefix(route.path, "/userinfo") {
			require.JSONEq(t, `{"error":"invalid_token","error_description":"The access token is invalid."}`, unparseable.body)
		} else {
			require.JSONEq(t, `{"error_code":"INVALID_TOKEN","error_description":"The access token is invalid."}`, unparseable.body)
		}

		for _, tc := range tokens {
			t.Run(route.name+", "+tc.name, func(t *testing.T) {
				before, err := database.GetUserById(context.Background(), nil, tc.user.Id)
				require.NoError(t, err)

				got := sendBearer(t, route, tc.token)

				assert.Equal(t, unparseable, got, "answered exactly as a token that does not parse")

				after, err := database.GetUserById(context.Background(), nil, tc.user.Id)
				require.NoError(t, err)
				assert.Equal(t, before.Email, after.Email, "the handler never ran")
			})
		}
	}
}

// TestBearerToken_AccessTokensWithAnAudienceArrayStillPass: the two access-token kinds reach the
// routes they reached before, including when aud is an array. Issuance writes two audiences as a
// []string and the parser hands the middleware []interface{}, so only a token through the real
// signer and parser shows the aud check reads the shape it will be given.
func TestBearerToken_AccessTokensWithAnAudienceArrayStillPass(t *testing.T) {
	secondResource := createTestResource(t, "bearer-aud-"+strings.ToLower(fake.LetterN(8)), "A second audience")
	require.NotZero(t, secondResource.Id)
	t.Cleanup(func() {
		assert.NoError(t, database.DeleteResource(context.Background(), nil, secondResource.Id))
	})
	secondPermission := createTestPermission(t, secondResource.Id, "read", "Read")
	require.NotZero(t, secondPermission.Id)
	secondScope := secondResource.ResourceIdentifier + ":" + secondPermission.PermissionIdentifier

	requireAudienceArray := func(t *testing.T, token string) {
		t.Helper()
		aud, ok := decodeJWTPayload(t, token)["aud"].([]interface{})
		require.True(t, ok, "aud should be an array")
		assert.ElementsMatch(t, []interface{}{builtin.AuthServerResourceIdentifier, secondResource.ResourceIdentifier}, aud)
	}

	t.Run("user access token at GET and form-body POST /userinfo", func(t *testing.T) {
		accessToken, user := createUserAccessTokenWithScope(t, "openid "+secondScope)
		requireAudienceArray(t, accessToken)

		for _, route := range bearerKindRoutes()[:2] {
			got := sendBearer(t, route, accessToken)
			require.Equal(t, http.StatusOK, got.status, "%s: %s", route.name, got.body)
			assert.Contains(t, got.body, `"sub":"`+user.Subject+`"`, route.name)
		}
	})

	t.Run("client credentials token at an admin route", func(t *testing.T) {
		clientSecret := fake.Password(32)
		clientSecretEncrypted, err := dataCipher.Encrypt(clientSecret)
		require.NoError(t, err)
		client := &record.Client{
			ClientIdentifier:         "bearer-aud-client-" + strings.ToLower(fake.LetterN(8)),
			Enabled:                  true,
			ClientCredentialsEnabled: true,
			ClientSecretEncrypted:    clientSecretEncrypted,
		}
		require.NoError(t, database.CreateClient(context.Background(), nil, client))
		t.Cleanup(func() {
			assert.NoError(t, database.DeleteClient(context.Background(), nil, client.Id))
		})

		authserverResource, err := database.GetResourceByResourceIdentifier(context.Background(), nil, builtin.AuthServerResourceIdentifier)
		require.NoError(t, err)
		permissions, err := database.GetPermissionsByResourceId(context.Background(), nil, authserverResource.Id)
		require.NoError(t, err)
		for i := range permissions {
			if permissions[i].PermissionIdentifier == builtin.ManagePermissionIdentifier {
				require.NoError(t, database.CreateClientPermission(context.Background(), nil,
					&record.ClientPermission{ClientId: client.Id, PermissionId: permissions[i].Id}))
			}
		}
		require.NoError(t, database.CreateClientPermission(context.Background(), nil,
			&record.ClientPermission{ClientId: client.Id, PermissionId: secondPermission.Id}))

		scope := builtin.AuthServerResourceIdentifier + ":" + builtin.ManagePermissionIdentifier + " " + secondScope
		data := postToTokenEndpoint(t, createHttpClient(t), appConfig.AuthServer.BaseURL+"/auth/token/", url.Values{
			"grant_type":    {"client_credentials"},
			"client_id":     {client.ClientIdentifier},
			"client_secret": {clientSecret},
			"scope":         {scope},
		})
		accessToken, ok := data["access_token"].(string)
		require.True(t, ok, "client credentials token should be issued: %v", data)
		requireAudienceArray(t, accessToken)

		got := sendBearer(t, bearerKindRoutes()[2], accessToken)
		assert.Equal(t, http.StatusOK, got.status, got.body)
	})
}

// TestBearerToken_NonIdTokenAsIdTokenHintIsRefused: at /auth/authorize a validly signed token of
// this server that is not an ID Token is refused as a hint, with the answer an unparseable hint
// gets. prompt=none from a browser with no session makes the answer immediate: a hint that passes
// goes on to login_required, a refused one stops at invalid_request.
func TestBearerToken_NonIdTokenAsIdTokenHintIsRefused(t *testing.T) {
	tokens, code, _, _ := userTokenResponseWithScope(t, "openid", nil)

	authorizeWithHint := func(t *testing.T, hint string) (string, string) {
		t.Helper()
		destUrl := appConfig.AuthServer.BaseURL + "/auth/authorize/?client_id=" + code.Client.ClientIdentifier +
			"&redirect_uri=" + url.QueryEscape(code.RedirectURI) +
			"&response_type=code" +
			"&code_challenge_method=S256" +
			"&code_challenge=" + oauth.GeneratePKCECodeChallenge(testCodeVerifier) +
			"&scope=openid" +
			"&state=" + fake.LetterN(8) +
			"&prompt=none" +
			"&id_token_hint=" + url.QueryEscape(hint)

		resp, err := createHttpClient(t).Get(destUrl)
		require.NoError(t, err)
		defer func() { _ = resp.Body.Close() }()
		require.Equal(t, http.StatusFound, resp.StatusCode)
		require.True(t, strings.HasPrefix(resp.Header.Get("Location"), code.RedirectURI),
			"answered at the client's redirect_uri: %s", resp.Header.Get("Location"))
		errorCode, errorDescription, _ := getErrorFromUrl(t, resp)
		return errorCode, errorDescription
	}

	idToken, ok := tokens["id_token"].(string)
	require.True(t, ok)
	errorCode, _ := authorizeWithHint(t, idToken)
	require.Equal(t, "login_required", errorCode, "the real ID token passes the hint check")

	unparseableCode, unparseableDescription := authorizeWithHint(t, "not-a-jwt")
	require.Equal(t, "invalid_request", unparseableCode)

	for _, kind := range []string{"access_token", "refresh_token"} {
		t.Run(kind, func(t *testing.T) {
			token, ok := tokens[kind].(string)
			require.True(t, ok, "the exchange yields a %s", kind)
			errorCode, errorDescription := authorizeWithHint(t, token)
			assert.Equal(t, unparseableCode, errorCode)
			assert.Equal(t, unparseableDescription, errorDescription)
		})
	}
}
