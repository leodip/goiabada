package integrationtests

import (
	"io"
	"net/http"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/leodip/goiabada/core/config"
	"github.com/leodip/goiabada/core/constants"
	"github.com/stretchr/testify/assert"
)

// extractSidClaim parses the access token (without verifying its signature)
// and returns the `sid` claim. Returns "" if the claim is absent or not a string.
func extractSidClaim(t *testing.T, accessToken string) string {
	t.Helper()
	tok, _, err := new(jwt.Parser).ParseUnverified(accessToken, jwt.MapClaims{})
	assert.NoError(t, err)
	claims, ok := tok.Claims.(jwt.MapClaims)
	assert.True(t, ok)
	if v, ok := claims["sid"].(string); ok {
		return v
	}
	return ""
}

// TestSession_AdminAPI_DeletedSessionRejectsBearer covers the broadened bearer
// surface: a user-bound admin access token (with `sid`) must be rejected at
// /api/v1/admin once its underlying UserSession is deleted, even though the
// JWT itself remains cryptographically valid until expiry. This is the
// guarantee that closes the auth-code reuse / RFC 6749 §4.1.2 gap.
func TestSession_AdminAPI_DeletedSessionRejectsBearer(t *testing.T) {
	scope := "openid " + constants.AuthServerResourceIdentifier + ":" + constants.ManagePermissionIdentifier
	accessToken, _ := createUserAccessTokenWithScope(t, scope)

	sid := extractSidClaim(t, accessToken)
	assert.NotEmpty(t, sid, "user-bound auth-code token must carry a sid claim")

	adminURL := config.GetAuthServer().BaseURL + "/api/v1/admin/users/search"

	// Pre-condition: token works while session is alive.
	resp := makeAPIRequest(t, "GET", adminURL, accessToken, nil)
	_ = resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode, "token should work before session deletion")

	// Delete the underlying user session out from under the token.
	session, err := database.GetUserSessionBySessionIdentifier(nil, sid)
	assert.NoError(t, err)
	assert.NotNil(t, session, "session should exist for sid %s", sid)
	err = database.DeleteUserSession(nil, session.Id)
	assert.NoError(t, err)

	// Post-condition: same token now rejected with 401 invalid_token.
	resp2 := makeAPIRequest(t, "GET", adminURL, accessToken, nil)
	defer func() { _ = resp2.Body.Close() }()
	assert.Equal(t, http.StatusUnauthorized, resp2.StatusCode, "token must be rejected once session is deleted")
	wwwAuth := resp2.Header.Get("WWW-Authenticate")
	assert.Contains(t, wwwAuth, `Bearer error="invalid_token"`)
	assert.Contains(t, wwwAuth, "Session has been terminated")

	body, _ := io.ReadAll(resp2.Body)
	assert.Contains(t, string(body), "Session has been terminated")
}

// TestSession_AccountAPI_DeletedSessionRejectsBearer verifies the same
// guarantee on the self-service /api/v1/account surface.
func TestSession_AccountAPI_DeletedSessionRejectsBearer(t *testing.T) {
	accessToken, _ := getUserAccessTokenWithAccountScope(t)

	sid := extractSidClaim(t, accessToken)
	assert.NotEmpty(t, sid, "account-scope token must carry a sid claim")

	accountURL := config.GetAuthServer().BaseURL + "/api/v1/account/profile"

	// Pre-condition: token works.
	resp := makeAPIRequest(t, "GET", accountURL, accessToken, nil)
	_ = resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode, "token should work before session deletion")

	// Delete the underlying user session.
	session, err := database.GetUserSessionBySessionIdentifier(nil, sid)
	assert.NoError(t, err)
	assert.NotNil(t, session, "session should exist for sid %s", sid)
	err = database.DeleteUserSession(nil, session.Id)
	assert.NoError(t, err)

	// Post-condition: 401 invalid_token.
	resp2 := makeAPIRequest(t, "GET", accountURL, accessToken, nil)
	defer func() { _ = resp2.Body.Close() }()
	assert.Equal(t, http.StatusUnauthorized, resp2.StatusCode)
	wwwAuth := resp2.Header.Get("WWW-Authenticate")
	assert.Contains(t, wwwAuth, `Bearer error="invalid_token"`)
	assert.Contains(t, wwwAuth, "Session has been terminated")
}

// TestSession_ClientCredentialsToken_NoSidPassesThrough verifies that
// client_credentials tokens (which have no `sid` claim) continue to work
// against the admin API: the new RequireValidSession middleware must
// pass them through untouched. Otherwise we would have broken every
// service-to-service caller in the process of fixing auth-code reuse.
func TestSession_ClientCredentialsToken_NoSidPassesThrough(t *testing.T) {
	accessToken, _ := createAdminClientWithToken(t)

	sid := extractSidClaim(t, accessToken)
	assert.Empty(t, sid, "client_credentials tokens must not carry a sid claim")

	adminURL := config.GetAuthServer().BaseURL + "/api/v1/admin/users/search"
	resp := makeAPIRequest(t, "GET", adminURL, accessToken, nil)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusOK, resp.StatusCode,
		"client_credentials token must pass RequireValidSession (no sid → no-op)")
}
