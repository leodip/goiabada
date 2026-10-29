package integration

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/leodip/goiabada/authserver/internal/fake"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/authserver/internal/signingkeys"
	"github.com/leodip/goiabada/core/api"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Access tokens follow RFC 9068 (#676 decisions 2, 3, 4 and 6). Every one carries the JOSE header
// typ at+jwt and the client_id of its client; those of the authorization code, refresh and password
// grants carry grant_id, their refresh token family's identifier; offline_access names authserver
// in aud. The auth server's own endpoints, /userinfo and the admin and account APIs, refuse an
// access token whose header is not at+jwt (one issued before the upgrade), whose iss is not the
// configured issuer, or whose client is disabled or gone, with 401 invalid_token.

// decodeJWTHeader decodes a JWT's JOSE header, unverified.
func decodeJWTHeader(t *testing.T, token string) map[string]interface{} {
	t.Helper()
	encoded, _, ok := strings.Cut(token, ".")
	require.True(t, ok, "a JWT has a header segment")
	raw, err := base64.RawURLEncoding.DecodeString(encoded)
	require.NoError(t, err)
	var header map[string]interface{}
	require.NoError(t, json.Unmarshal(raw, &header))
	return header
}

// resignWithCurrentKey signs claims with the server's current signing key under the given header
// typ, as the server would have: an empty typ leaves the library's own, JWT.
func resignWithCurrentKey(t *testing.T, claims jwt.MapClaims, typ string) string {
	t.Helper()
	keyPair, err := database.GetCurrentSigningKey(context.Background(), nil)
	require.NoError(t, err)
	privKey, err := signingkeys.ParsePrivateKey(dataCipher, keyPair)
	require.NoError(t, err)
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = keyPair.KeyIdentifier
	if typ != "" {
		token.Header["typ"] = typ
	}
	signed, err := token.SignedString(privKey)
	require.NoError(t, err)
	return signed
}

// assertAPIRefusesToken asserts an admin or account API call with accessToken answers 401
// INVALID_TOKEN, "The access token is invalid.", in the challenge and the body.
func assertAPIRefusesToken(t *testing.T, target, accessToken string) {
	t.Helper()
	resp := makeAPIRequest(t, http.MethodGet, appConfig.AuthServer.BaseURL+target, accessToken, nil)
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	require.Equal(t, http.StatusUnauthorized, resp.StatusCode, "%s: %s", target, string(body))
	assert.Equal(t, `Bearer realm="goiabada", error="invalid_token", error_description="The access token is invalid."`,
		resp.Header.Get("WWW-Authenticate"), target)
	var errResp api.ErrorResponse
	require.NoError(t, json.Unmarshal(body, &errResp))
	assert.Equal(t, api.ErrorResponse{ErrorCode: "INVALID_TOKEN", ErrorDescription: "The access token is invalid."}, errResp, target)
}

// assertAPIAdmitsToken asserts an admin or account API call with accessToken answers 200.
func assertAPIAdmitsToken(t *testing.T, target, accessToken string) {
	t.Helper()
	resp := makeAPIRequest(t, http.MethodGet, appConfig.AuthServer.BaseURL+target, accessToken, nil)
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	require.Equal(t, http.StatusOK, resp.StatusCode, "%s: %s", target, string(body))
}

func setClientEnabled(t *testing.T, clientId int64, enabled bool) {
	t.Helper()
	client, err := database.GetClientById(context.Background(), nil, clientId)
	require.NoError(t, err)
	require.NotNil(t, client)
	client.Enabled = enabled
	require.NoError(t, database.UpdateClient(context.Background(), nil, client))
}

// The code exchange and every refresh after it: the at+jwt header, the client, and one grant_id,
// the jti of the grant's first refresh token, which its row records as the family's.
func TestRFC9068_AuthorizationCodeGrantAndItsRefreshes(t *testing.T) {
	data, code, httpClient, clientSecret := userTokenResponseWithScope(t, "openid", nil)
	accessToken := data["access_token"].(string)
	refreshToken := data["refresh_token"].(string)

	assert.Equal(t, "at+jwt", decodeJWTHeader(t, accessToken)["typ"], "the access token's header")
	assert.Equal(t, "JWT", decodeJWTHeader(t, data["id_token"].(string))["typ"], "the ID token keeps its header")
	assert.Equal(t, "JWT", decodeJWTHeader(t, refreshToken)["typ"], "the refresh token keeps its header")

	claims := decodeJWTPayload(t, accessToken)
	assert.Equal(t, code.Client.ClientIdentifier, claims["client_id"])
	firstJti := decodeJWTPayload(t, refreshToken)["jti"].(string)
	assert.Equal(t, firstJti, claims["grant_id"], "the grant is its first refresh token's jti")
	row, err := database.GetRefreshTokenByJti(context.Background(), nil, firstJti)
	require.NoError(t, err)
	require.NotNil(t, row)
	assert.Equal(t, firstJti, row.FirstRefreshTokenJti, "the row records the same family")

	for i := 1; i <= 2; i++ {
		status, refreshed := refreshAuthCodeGrant(t, httpClient, code, clientSecret, refreshToken, "")
		require.Equal(t, http.StatusOK, status, "refresh %d: %v", i, refreshed)
		refreshedAccess := refreshed["access_token"].(string)
		refreshToken = refreshed["refresh_token"].(string)

		assert.Equal(t, "at+jwt", decodeJWTHeader(t, refreshedAccess)["typ"], "refresh %d", i)
		refreshedClaims := decodeJWTPayload(t, refreshedAccess)
		assert.Equal(t, code.Client.ClientIdentifier, refreshedClaims["client_id"], "refresh %d", i)
		assert.Equal(t, firstJti, refreshedClaims["grant_id"], "refresh %d stays in its grant", i)
		assert.NotEqual(t, firstJti, decodeJWTPayload(t, refreshToken)["jti"], "refresh %d rotates its refresh token", i)
		assertUserinfoAdmits(t, refreshedAccess, code.User.Subject)
	}
}

func TestRFC9068_PasswordGrantAndItsRefresh(t *testing.T) {
	enableROPCGlobally(t)
	clientSecret := fake.Password(32)
	password := fake.Password(12)
	client := createROPCClient(t, clientSecret, false)
	user := createROPCUser(t, password)
	httpClient := createHttpClient(t)

	data := postToTokenEndpoint(t, httpClient, appConfig.AuthServer.BaseURL+"/auth/token/", url.Values{
		"grant_type":    {"password"},
		"client_id":     {client.ClientIdentifier},
		"client_secret": {clientSecret},
		"username":      {user.Email},
		"password":      {password},
		"scope":         {"openid"},
	})
	accessToken := data["access_token"].(string)
	refreshToken := data["refresh_token"].(string)

	assert.Equal(t, "at+jwt", decodeJWTHeader(t, accessToken)["typ"])
	claims := decodeJWTPayload(t, accessToken)
	assert.Equal(t, client.ClientIdentifier, claims["client_id"])
	firstJti := decodeJWTPayload(t, refreshToken)["jti"]
	assert.Equal(t, firstJti, claims["grant_id"])

	status, refreshed := refreshWithScope(t, httpClient, client.ClientIdentifier, clientSecret, refreshToken, "")
	require.Equal(t, http.StatusOK, status, "%v", refreshed)
	refreshedClaims := decodeJWTPayload(t, refreshed["access_token"].(string))
	assert.Equal(t, firstJti, refreshedClaims["grant_id"])
	assert.Equal(t, client.ClientIdentifier, refreshedClaims["client_id"])
	assertUserinfoAdmits(t, refreshed["access_token"].(string), user.Subject)
}

// The client credentials grant issues no refresh token, so its token names no grant.
func TestRFC9068_ClientCredentialsGrant(t *testing.T) {
	accessToken, client := createAdminClientWithToken(t)

	assert.Equal(t, "at+jwt", decodeJWTHeader(t, accessToken)["typ"])
	claims := decodeJWTPayload(t, accessToken)
	assert.Equal(t, client.ClientIdentifier, claims["client_id"])
	assert.Equal(t, client.ClientIdentifier, claims["sub"])
	assert.NotContains(t, claims, "grant_id")
	assertAPIAdmitsToken(t, "/api/v1/admin/resources", accessToken)
}

// offline_access names authserver in aud, beside a resource's, and the scope is the grant's
// (#676 decision 3). Through the password grant, since a sign-in asking for offline_access asks the
// user for consent first.
func TestRFC9068_OfflineAccessNamesTheAuthServer(t *testing.T) {
	enableROPCGlobally(t)

	passwordGrant := func(t *testing.T, scope string, grant func(user *record.User)) map[string]interface{} {
		clientSecret := fake.Password(32)
		password := fake.Password(12)
		client := createROPCClient(t, clientSecret, false)
		user := createROPCUser(t, password)
		if grant != nil {
			grant(user)
		}
		return postToTokenEndpoint(t, createHttpClient(t), appConfig.AuthServer.BaseURL+"/auth/token/", url.Values{
			"grant_type":    {"password"},
			"client_id":     {client.ClientIdentifier},
			"client_secret": {clientSecret},
			"username":      {user.Email},
			"password":      {password},
			"scope":         {scope},
		})
	}

	t.Run("beside a resource", func(t *testing.T) {
		resource := "rfc9068-" + strings.ToLower(fake.LetterN(8))
		permission := createPermissionWithId(t, createResourceWithId(t, resource).Id, "read")
		scope := "offline_access " + resource + ":read"

		data := passwordGrant(t, scope, func(user *record.User) { assignPermissionToUser(t, user.Id, permission.Id) })

		assert.Equal(t, scope, data["scope"])
		claims := decodeJWTPayload(t, data["access_token"].(string))
		assert.Equal(t, []interface{}{"authserver", resource}, claims["aud"])
		assert.Equal(t, scope, claims["scope"])
	})

	t.Run("with a claim scope", func(t *testing.T) {
		data := passwordGrant(t, "openid offline_access", nil)

		assert.Equal(t, "openid offline_access", data["scope"])
		assert.Equal(t, "authserver", decodeJWTPayload(t, data["access_token"].(string))["aud"])
	})
}

// An access token issued before the upgrade carries the header typ JWT, and RFC 9068 section 4 says
// a resource server MUST refuse it (#676 decision 4). Each token is a real one re-signed with the
// current key under the old header, its claims untouched.
func TestRFC9068_ATokenFromBeforeTheUpgradeIsRefused(t *testing.T) {
	t.Run("at /userinfo", func(t *testing.T) {
		data, code, _, _ := userTokenResponseWithScope(t, "openid", nil)
		claims := jwt.MapClaims(decodeJWTPayload(t, data["access_token"].(string)))

		assertUserinfoAdmits(t, resignWithCurrentKey(t, claims, "at+jwt"), code.User.Subject)
		assertUserinfoRefuses(t, resignWithCurrentKey(t, claims, ""), http.StatusUnauthorized, "invalid_token")
	})

	t.Run("at the account API", func(t *testing.T) {
		_, accessToken, _ := getUserAccessTokenAndCodeForAccountScope(t)
		claims := jwt.MapClaims(decodeJWTPayload(t, accessToken))

		assertAPIAdmitsToken(t, "/api/v1/account/profile", resignWithCurrentKey(t, claims, "at+jwt"))
		assertAPIRefusesToken(t, "/api/v1/account/profile", resignWithCurrentKey(t, claims, ""))
	})

	t.Run("a client's token at the admin API", func(t *testing.T) {
		accessToken, _ := createAdminClientWithToken(t)
		claims := jwt.MapClaims(decodeJWTPayload(t, accessToken))

		assertAPIAdmitsToken(t, "/api/v1/admin/resources", resignWithCurrentKey(t, claims, "at+jwt"))
		assertAPIRefusesToken(t, "/api/v1/admin/resources", resignWithCurrentKey(t, claims, "JWT"))
	})
}

// The iss must be exactly the configured issuer, so changing the issuer setting ends every access
// token issued under the old one at the auth server's own endpoints.
func TestRFC9068_ChangingTheIssuerEndsTheAccessTokensIssuedUnderTheOldOne(t *testing.T) {
	restoreSettings(t)
	data, code, _, _ := userTokenResponseWithScope(t, "openid", nil)
	userToken := data["access_token"].(string)
	clientToken, _ := createAdminClientWithToken(t)
	assertUserinfoAdmits(t, userToken, code.User.Subject)
	assertAPIAdmitsToken(t, "/api/v1/admin/resources", clientToken)

	changeSettings(t, func(settings *record.Settings) {
		settings.Issuer = "https://issuer-" + strings.ToLower(fake.LetterN(6)) + ".example.org"
	})

	assertUserinfoRefuses(t, userToken, http.StatusUnauthorized, "invalid_token")
	assertAPIRefusesToken(t, "/api/v1/admin/resources", clientToken)

	// A token issued under the new issuer works.
	newToken, _ := createAdminClientWithToken(t)
	assertAPIAdmitsToken(t, "/api/v1/admin/resources", newToken)
}

// A token whose client is disabled is refused while the client stays disabled, and works again
// once it is enabled before the token expires; a deleted client's never does (#676 decision 6).
func TestRFC9068_ATokenOfADisabledOrDeletedClientIsRefused(t *testing.T) {
	t.Run("a user's token at /userinfo", func(t *testing.T) {
		data, code, _, _ := userTokenResponseWithScope(t, "openid", nil)
		accessToken := data["access_token"].(string)
		assertUserinfoAdmits(t, accessToken, code.User.Subject)

		setClientEnabled(t, code.Client.Id, false)
		assertUserinfoRefuses(t, accessToken, http.StatusUnauthorized, "invalid_token")

		setClientEnabled(t, code.Client.Id, true)
		assertUserinfoAdmits(t, accessToken, code.User.Subject)
	})

	t.Run("a user's token at the account API", func(t *testing.T) {
		_, accessToken, code := getUserAccessTokenAndCodeForAccountScope(t)
		assertAPIAdmitsToken(t, "/api/v1/account/profile", accessToken)

		setClientEnabled(t, code.Client.Id, false)
		assertAPIRefusesToken(t, "/api/v1/account/profile", accessToken)
	})

	t.Run("a client's token at the admin API", func(t *testing.T) {
		accessToken, client := createAdminClientWithToken(t)
		assertAPIAdmitsToken(t, "/api/v1/admin/resources", accessToken)

		setClientEnabled(t, client.Id, false)
		assertAPIRefusesToken(t, "/api/v1/admin/resources", accessToken)

		setClientEnabled(t, client.Id, true)
		assertAPIAdmitsToken(t, "/api/v1/admin/resources", accessToken)
	})

	t.Run("a deleted client's token", func(t *testing.T) {
		data, code, _, _ := userTokenResponseWithScope(t, "openid", nil)
		accessToken := data["access_token"].(string)
		assertUserinfoAdmits(t, accessToken, code.User.Subject)

		require.NoError(t, database.DeleteClient(context.Background(), nil, code.Client.Id))
		assertUserinfoRefuses(t, accessToken, http.StatusUnauthorized, "invalid_token")
	})
}
