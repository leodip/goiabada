package integrationtests

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/leodip/goiabada/authserver/internal/config"
	"github.com/leodip/goiabada/authserver/internal/models"
	"github.com/leodip/goiabada/authserver/internal/signingkeys"
	"github.com/leodip/goiabada/authserver/internal/testutil/fake"
	"github.com/leodip/goiabada/core/api"
	"github.com/leodip/goiabada/core/constants"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// /userinfo takes a user's access token whose scope carries openid (#449). OIDC Core 1.0 section 5.3
// describes the endpoint as the one a client reaches "using an Access Token obtained through OpenID
// Connect Authentication", and every such token carries openid. Until #449 it gated on an
// authserver:userinfo scope that issuance appended to any token with a claim scope, which put a
// scope in every reported scope the client never asked for, and a refresh echoing it was refused.

// userinfoGet calls GET /userinfo with the token in the Authorization header.
func userinfoGet(t *testing.T, accessToken string) *http.Response {
	t.Helper()
	return makeAPIRequest(t, "GET", config.GetAuthServer().BaseURL+"/userinfo", accessToken, nil)
}

// userinfoPost calls POST /userinfo with the token as a form-body access_token, which OIDC Core 1.0
// section 5.3.1 permits and which reaches the bearer middleware by a separate extraction path.
func userinfoPost(t *testing.T, accessToken string) *http.Response {
	t.Helper()
	form := url.Values{"access_token": {accessToken}}
	req, err := http.NewRequest("POST", config.GetAuthServer().BaseURL+"/userinfo", strings.NewReader(form.Encode()))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := createHttpClient(t).Do(req)
	require.NoError(t, err)
	return resp
}

// assertUserinfoAdmits calls /userinfo by GET and by POST and asserts each answers 200 for sub.
func assertUserinfoAdmits(t *testing.T, accessToken string, sub string) {
	t.Helper()
	for method, call := range map[string]func(*testing.T, string) *http.Response{"GET": userinfoGet, "POST": userinfoPost} {
		resp := call(t, accessToken)
		body, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if !assert.Equal(t, http.StatusOK, resp.StatusCode, "%s /userinfo: %s", method, string(body)) {
			continue
		}
		var claims map[string]interface{}
		require.NoError(t, json.Unmarshal(body, &claims))
		assert.Equal(t, sub, claims["sub"], "%s /userinfo", method)
	}
}

// assertUserinfoRefuses calls /userinfo by GET and by POST and asserts each answers status, with
// the WWW-Authenticate error RFC 6750 section 3.1 names for it and, when errorCode is set, that
// error_code in the body.
func assertUserinfoRefuses(t *testing.T, accessToken string, status int, bearerError string, errorCode string) {
	t.Helper()
	for method, call := range map[string]func(*testing.T, string) *http.Response{"GET": userinfoGet, "POST": userinfoPost} {
		resp := call(t, accessToken)
		body, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		assert.Equal(t, status, resp.StatusCode, "%s /userinfo: %s", method, string(body))
		assert.Contains(t, resp.Header.Get("WWW-Authenticate"), `error="`+bearerError+`"`, "%s /userinfo", method)
		if errorCode != "" {
			var errResp api.ErrorResponse
			_ = json.Unmarshal(body, &errResp)
			assert.Equal(t, errorCode, errResp.ErrorCode, "%s /userinfo: %s", method, string(body))
		}
	}
}

// joinGroupCarriedInAccessToken puts user in a fresh group whose identifier rides in the access
// token, and returns the identifier.
func joinGroupCarriedInAccessToken(t *testing.T, user *models.User) string {
	t.Helper()
	group := &models.Group{
		GroupIdentifier:      "userinfo-group-" + strings.ToLower(fake.LetterN(8)),
		IncludeInIdToken:     true,
		IncludeInAccessToken: true,
	}
	require.NoError(t, database.CreateGroup(context.Background(), nil, group))
	require.NoError(t, database.CreateUserGroup(context.Background(), nil, &models.UserGroup{UserId: user.Id, GroupId: group.Id}))
	return group.GroupIdentifier
}

// refreshAuthCodeGrant presents an authorization code grant's refresh token, with `scope` when
// scope is not empty, and returns the status and the response.
func refreshAuthCodeGrant(t *testing.T, httpClient *http.Client, code *models.Code, clientSecret string,
	refreshToken string, scope string) (int, map[string]interface{}) {
	t.Helper()
	return refreshWithScope(t, httpClient, code.Client.ClientIdentifier, clientSecret, refreshToken, scope)
}

// TestUserinfo_UserTokensWithOpenidAreAdmitted walks every flow that issues a user an access token
// with openid to /userinfo, by GET and by POST. Each reports exactly the scope it was granted, and
// writes exactly that into the access token: nothing is appended any more.
func TestUserinfo_UserTokensWithOpenidAreAdmitted(t *testing.T) {
	t.Run("authorization code", func(t *testing.T) {
		const grant = "openid profile email"
		data, code, _, _ := userTokenResponseWithScope(t, grant, nil)

		assert.Equal(t, grant, data["scope"])
		accessToken := data["access_token"].(string)
		assert.Equal(t, grant, decodeJWTPayload(t, accessToken)["scope"])
		assertUserinfoAdmits(t, accessToken, code.User.Subject)
	})

	t.Run("authorization code refresh", func(t *testing.T) {
		const grant = "openid profile email"
		data, code, httpClient, clientSecret := userTokenResponseWithScope(t, grant, nil)

		status, refreshed := refreshAuthCodeGrant(t, httpClient, code, clientSecret, data["refresh_token"].(string), "")
		require.Equal(t, http.StatusOK, status, "refresh: %v", refreshed)
		assert.Equal(t, grant, refreshed["scope"])
		accessToken := refreshed["access_token"].(string)
		assert.Equal(t, grant, decodeJWTPayload(t, accessToken)["scope"])
		assertUserinfoAdmits(t, accessToken, code.User.Subject)
	})

	t.Run("implicit token", func(t *testing.T) {
		const grant = "openid profile"
		tokens, user := implicitTokenResponse(t, "token", grant)

		assert.Equal(t, grant, tokens["scope"])
		assert.Equal(t, grant, decodeJWTPayload(t, tokens["access_token"])["scope"])
		assertUserinfoAdmits(t, tokens["access_token"], user.Subject)
	})

	t.Run("implicit id_token token", func(t *testing.T) {
		const grant = "openid email"
		tokens, user := implicitTokenResponse(t, "id_token token", grant)

		assert.NotEmpty(t, tokens["id_token"])
		assert.Equal(t, grant, tokens["scope"])
		assert.Equal(t, grant, decodeJWTPayload(t, tokens["access_token"])["scope"])
		assertUserinfoAdmits(t, tokens["access_token"], user.Subject)
	})

	t.Run("ROPC", func(t *testing.T) {
		data, user := ropcTokenResponse(t, "openid", nil)

		assert.Equal(t, "openid", data["scope"])
		accessToken := data["access_token"].(string)
		assert.Equal(t, "openid", decodeJWTPayload(t, accessToken)["scope"])
		assertUserinfoAdmits(t, accessToken, user.Subject)
	})

	t.Run("ROPC refresh", func(t *testing.T) {
		data, user := ropcTokenResponse(t, "openid", nil)

		status, refreshed := refreshROPCTokenResponse(t, data["refresh_token"].(string), "")
		require.Equal(t, http.StatusOK, status, "refresh: %v", refreshed)
		assert.Equal(t, "openid", refreshed["scope"])
		accessToken := refreshed["access_token"].(string)
		assert.Equal(t, "openid", decodeJWTPayload(t, accessToken)["scope"])
		assertUserinfoAdmits(t, accessToken, user.Subject)
	})
}

// TestUserinfo_RefreshEchoingTheReportedScope sends back, as the refresh's scope, exactly the scope
// the first response reported, which RFC 6749 section 6 permits for any scope "originally granted".
// Keep this: both answered invalid_scope before #449, because the reported scope carried an
// appended authserver:userinfo the grant did not hold.
func TestUserinfo_RefreshEchoingTheReportedScope(t *testing.T) {
	t.Run("authorization code", func(t *testing.T) {
		data, code, httpClient, clientSecret := userTokenResponseWithScope(t, "openid profile email", nil)
		reported := data["scope"].(string)

		status, refreshed := refreshAuthCodeGrant(t, httpClient, code, clientSecret, data["refresh_token"].(string), reported)
		require.Equal(t, http.StatusOK, status, "refresh: %v", refreshed)
		assert.Equal(t, reported, refreshed["scope"])
	})

	t.Run("ROPC", func(t *testing.T) {
		data, _ := ropcTokenResponse(t, "openid", nil)
		reported := data["scope"].(string)

		status, refreshed := refreshROPCTokenResponse(t, data["refresh_token"].(string), reported)
		require.Equal(t, http.StatusOK, status, "refresh: %v", refreshed)
		assert.Equal(t, reported, refreshed["scope"])
	})
}

// TestUserinfo_LegacyROPCGrantNamingUserinfo is an ROPC refresh token whose stored grant names
// authserver:userinfo, as one issued before its refresh token recorded the undecorated grant does.
// The refresh re-checks the scope against the user's permissions, finds none, and answers
// invalid_grant before the token is spent. The order is load-bearing: the refused refresh runs
// first, while the token is live, so the second refresh succeeding proves the first did not spend
// it, and narrowing the scope is the way out a client already has.
func TestUserinfo_LegacyROPCGrantNamingUserinfo(t *testing.T) {
	data, _ := ropcTokenResponse(t, "openid", nil)
	refreshToken := data["refresh_token"].(string)

	row := refreshTokenRowByJti(t, refreshToken)
	row.Scope = "openid authserver:userinfo"
	require.NoError(t, database.UpdateRefreshToken(context.Background(), nil, row))

	status, refused := refreshROPCTokenResponse(t, refreshToken, "")
	assert.Equal(t, http.StatusBadRequest, status)
	assert.Equal(t, "invalid_grant", refused["error"])
	assert.Equal(t,
		"Scope 'authserver:userinfo' is not recognized. The user does not have the 'authserver:userinfo' permission.",
		refused["error_description"])

	status, refreshed := refreshROPCTokenResponse(t, refreshToken, "openid")
	require.Equal(t, http.StatusOK, status, "the refused refresh must not have spent the token: %v", refreshed)
	assert.Equal(t, "openid", refreshed["scope"])
}

// TestUserinfo_TokenWithoutOpenidIsRefused is a user's access token that carries no openid: it is
// refused at the scope check with 403 insufficient_scope, RFC 6750 section 3.1's answer for a token
// that "requires higher privileges than provided by the access token".
func TestUserinfo_TokenWithoutOpenidIsRefused(t *testing.T) {
	accessToken, _ := createUserAccessTokenWithScope(t,
		constants.AuthServerResourceIdentifier+":"+constants.ManageAccountPermissionIdentifier)

	assertUserinfoRefuses(t, accessToken, http.StatusForbidden, "insufficient_scope", "INSUFFICIENT_SCOPE")
}

// TestUserinfo_ClaimScopesWithoutOpenid pins #449 decision 2: a claim scope without openid is still
// issued, at the authorization endpoint and at ROPC, and cannot reach /userinfo. OIDC Core 1.0
// section 3.1.2.1 leaves such a request "entirely unspecified", and groups keeps putting its claim
// into the access token without openid, so the token is useful and refusing the request would break
// it. Each is issued with no ID token, reports the scope it asked for, and names authserver as an
// audience. Keep this: scope=profile reached /userinfo with 200 before #449.
func TestUserinfo_ClaimScopesWithoutOpenid(t *testing.T) {
	assertClaimScopeToken := func(t *testing.T, data map[string]interface{}, scope string, groupIdentifier string) {
		t.Helper()
		assert.Nil(t, data["id_token"], "no ID token without openid")
		assert.Equal(t, scope, data["scope"])
		accessToken := data["access_token"].(string)
		claims := decodeJWTPayload(t, accessToken)
		assert.Equal(t, scope, claims["scope"])
		assert.Equal(t, constants.AuthServerResourceIdentifier, claims["aud"])
		if groupIdentifier != "" {
			assert.Equal(t, []interface{}{groupIdentifier}, claims["groups"])
		}
		assertUserinfoRefuses(t, accessToken, http.StatusForbidden, "insufficient_scope", "INSUFFICIENT_SCOPE")
	}

	for _, scope := range []string{"profile", "groups"} {
		t.Run("authorization endpoint/"+scope, func(t *testing.T) {
			var groupIdentifier string
			data, _, _, _ := userTokenResponseWithScope(t, scope, func(user *models.User) {
				if scope == "groups" {
					groupIdentifier = joinGroupCarriedInAccessToken(t, user)
				}
			})
			assertClaimScopeToken(t, data, scope, groupIdentifier)
		})

		t.Run("ROPC/"+scope, func(t *testing.T) {
			var groupIdentifier string
			data, _ := ropcTokenResponse(t, scope, func(user *models.User) {
				if scope == "groups" {
					groupIdentifier = joinGroupCarriedInAccessToken(t, user)
				}
			})
			assertClaimScopeToken(t, data, scope, groupIdentifier)
		})
	}
}

// TestUserinfo_EndedSessionIsRefused is a session-bound access token presented after its session
// ended: 401 invalid_token, RFC 6750 section 3.1's answer for a token that is "revoked ... or
// invalid for other reasons", on both registrations.
func TestUserinfo_EndedSessionIsRefused(t *testing.T) {
	data, code, _, _ := userTokenResponseWithScope(t, "openid", nil)
	accessToken := data["access_token"].(string)
	assertUserinfoAdmits(t, accessToken, code.User.Subject)

	session, err := database.GetUserSessionBySessionIdentifier(context.Background(), nil, code.SessionIdentifier)
	require.NoError(t, err)
	require.NotNil(t, session, "the code must be bound to a live session")
	require.NoError(t, database.DeleteUserSession(context.Background(), nil, session.Id))

	assertUserinfoRefuses(t, accessToken, http.StatusUnauthorized, "invalid_token", "")
}

// TestUserinfo_LegacyAccessTokenCarryingTheAppendedScope is an access token issued before #449,
// presented after it: its scope carries both openid and the appended authserver:userinfo. It is
// admitted on its openid, so no live token loses /userinfo across the upgrade. The token is a real
// one re-signed with the current signing key, its scope claim set to what issuance used to write.
func TestUserinfo_LegacyAccessTokenCarryingTheAppendedScope(t *testing.T) {
	data, code, _, _ := userTokenResponseWithScope(t, "openid", nil)

	claims := jwt.MapClaims(decodeJWTPayload(t, data["access_token"].(string)))
	claims["scope"] = "openid authserver:userinfo"

	keyPair, err := database.GetCurrentSigningKey(context.Background(), nil)
	require.NoError(t, err)
	privKey, err := signingkeys.ParsePrivateKey(keyPair)
	require.NoError(t, err)
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = keyPair.KeyIdentifier
	legacyAccessToken, err := token.SignedString(privKey)
	require.NoError(t, err)

	resp := userinfoGet(t, legacyAccessToken)
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	require.Equal(t, http.StatusOK, resp.StatusCode, "body: %s", string(body))
	var userinfo map[string]interface{}
	require.NoError(t, json.Unmarshal(body, &userinfo))
	assert.Equal(t, code.User.Subject, userinfo["sub"])
}
