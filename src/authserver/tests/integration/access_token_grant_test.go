package integration

import (
	"context"
	"database/sql"
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"testing"
	"time"

	"github.com/leodip/goiabada/authserver/internal/fake"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// An access token ends with its grant (#676 decision 1). A token carrying grant_id is live at the
// auth server's own endpoints, /userinfo and the admin and account APIs, only while its refresh
// token family has no revocation record and still has a member that is not revoked. So each way a
// grant is revoked refuses its access tokens at once, 401 invalid_token "The access token is
// invalid.", where before they lived until they expired: consent withdrawn, the client made public,
// the session behind an offline grant ended, a replayed refresh token. A rotation keeps the grant
// live, and so does a session that merely expired.

// assertUserinfoRefusesTheToken asserts /userinfo answers 401 invalid_token, "The access token is
// invalid.", to accessToken, by GET and by POST, in the challenge and the body.
func assertUserinfoRefusesTheToken(t *testing.T, accessToken string) {
	t.Helper()
	for method, call := range map[string]func(*testing.T, string) *http.Response{"GET": userinfoGet, "POST": userinfoPost} {
		resp := call(t, accessToken)
		body, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		require.Equal(t, http.StatusUnauthorized, resp.StatusCode, "%s /userinfo: %s", method, string(body))
		assert.Equal(t, `Bearer realm="goiabada", error="invalid_token", error_description="The access token is invalid."`,
			resp.Header.Get("WWW-Authenticate"), "%s /userinfo", method)
		var errResp map[string]string
		require.NoError(t, json.Unmarshal(body, &errResp), "%s /userinfo: %s", method, string(body))
		assert.Equal(t, map[string]string{"error": "invalid_token", "error_description": "The access token is invalid."},
			errResp, "%s /userinfo", method)
	}
}

// deleteThroughAdminAPI sends DELETE target with adminToken and requires 200.
func deleteThroughAdminAPI(t *testing.T, adminToken, target string) {
	t.Helper()
	resp := makeAPIRequest(t, http.MethodDelete, appConfig.AuthServer.BaseURL+target, adminToken, nil)
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	require.Equal(t, http.StatusOK, resp.StatusCode, "DELETE %s: %s", target, string(body))
}

// A user withdraws their consent to a client: every grant they hold with it is revoked, and the
// access tokens of those grants are refused at /userinfo and the account API, while their grant
// with another client goes on working.
func TestAccessTokenGrant_ConsentWithdrawnEndsItsAccessTokens(t *testing.T) {
	adminToken, _ := createAdminClientWithToken(t)
	_, accessToken, code := getUserAccessTokenAndCodeForAccountScope(t)
	t.Cleanup(func() { _ = database.DeleteClient(context.Background(), nil, code.ClientId) })
	require.Contains(t, decodeJWTPayload(t, accessToken), "grant_id", "the token names its grant")

	// The consent the user gave on the consent screen, or one standing for it when the client did
	// not ask: the row the withdrawal endpoints delete.
	consent, err := database.GetConsentByUserIdAndClientId(context.Background(), nil, code.UserId, code.ClientId)
	require.NoError(t, err)
	if consent == nil {
		consent = &record.UserConsent{
			UserId:    code.UserId,
			ClientId:  code.ClientId,
			Scope:     code.Scope,
			GrantedAt: sql.NullTime{Time: time.Now().UTC(), Valid: true},
		}
		require.NoError(t, database.CreateUserConsent(context.Background(), nil, consent))
	}

	// The same user's grant with another client, from a browser of its own.
	otherSecret := fake.LetterN(32)
	password := fake.Password(12)
	user, err := database.GetUserById(context.Background(), nil, code.UserId)
	require.NoError(t, err)
	setUserPassword(t, user, password)
	otherHttpClient, otherCode := createAuthCode(t, otherSecret, "openid",
		authCodeOptions{user: user, userPassword: password})
	t.Cleanup(func() { _ = database.DeleteClient(context.Background(), nil, otherCode.ClientId) })
	otherToken := redeemCode(t, otherHttpClient, otherCode, otherSecret)["access_token"].(string)

	// The positive control: the token works before the withdrawal.
	assertUserinfoAdmits(t, accessToken, code.User.Subject)
	assertAPIAdmitsToken(t, "/api/v1/account/profile", accessToken)
	assertUserinfoAdmits(t, otherToken, code.User.Subject)

	deleteThroughAdminAPI(t, adminToken, "/api/v1/admin/user-consents/"+strconv.FormatInt(consent.Id, 10))

	assertUserinfoRefusesTheToken(t, accessToken)
	assertAPIRefusesToken(t, "/api/v1/account/profile", accessToken)
	assertUserinfoAdmits(t, otherToken, code.User.Subject)
}

// An administrator makes a confidential client public: its grants are revoked, and so their access
// tokens are refused, though the client itself stays enabled.
func TestAccessTokenGrant_ClientMadePublicEndsItsAccessTokens(t *testing.T) {
	adminToken, _ := createAdminClientWithToken(t)
	clientSecret := fake.LetterN(32)
	httpClient, code := createAuthCode(t, clientSecret, "openid profile email")
	t.Cleanup(func() { _ = database.DeleteClient(context.Background(), nil, code.ClientId) })
	accessToken := redeemCode(t, httpClient, code, clientSecret)["access_token"].(string)
	assertUserinfoAdmits(t, accessToken, code.User.Subject)

	flipToPublic(t, adminToken, code.ClientId)

	client, err := database.GetClientById(context.Background(), nil, code.ClientId)
	require.NoError(t, err)
	require.True(t, client.Enabled, "the client stays enabled, so only its grant can refuse the token")
	assertUserinfoRefusesTheToken(t, accessToken)
}

// Ending the session an offline grant came from revokes the grant, so its access token, which
// names no session, is refused too. A session that merely expired revokes nothing, and the same
// token goes on working: TestCredentialChange_OfflineTokenWorksAfterSessionDeletion holds that half.
func TestAccessTokenGrant_EndingTheSessionOfAnOfflineGrantEndsItsAccessTokens(t *testing.T) {
	adminToken, _ := createAdminClientWithToken(t)
	grant := createOfflineGrant(t)
	require.Empty(t, extractSidClaim(t, grant.accessToken), "an offline grant's access token names no session")
	require.Contains(t, decodeJWTPayload(t, grant.accessToken), "grant_id", "the token names its grant")
	assertUserinfoAdmits(t, grant.accessToken, grant.user.Subject)
	assertAPIAdmitsToken(t, "/api/v1/account/profile", grant.accessToken)

	session, err := database.GetUserSessionBySessionIdentifier(context.Background(), nil, grant.sessionIdentifier)
	require.NoError(t, err)
	require.NotNil(t, session)
	deleteThroughAdminAPI(t, adminToken, "/api/v1/admin/user-sessions/"+strconv.FormatInt(session.Id, 10))

	assertUserinfoRefusesTheToken(t, grant.accessToken)
	assertAPIRefusesToken(t, "/api/v1/account/profile", grant.accessToken)
}

// A credential change revokes the user's authentication state, every grant included, and their
// access tokens are refused. The generation check answers first, for an offline token as for a
// session-bound one, so this holds what the change already did.
func TestAccessTokenGrant_RevokingTheUsersAuthStateEndsItsAccessTokens(t *testing.T) {
	grant := createOfflineGrant(t)
	assertUserinfoAdmits(t, grant.accessToken, grant.user.Subject)

	resetPasswordFor(t, grant.user, fake.Password(20))

	assertUserinfoRefuses(t, grant.accessToken, http.StatusUnauthorized, "invalid_token")
}

// A refresh token presented twice is a replay: its family is recorded as revoked, and every access
// token of the grant is refused, the latest included.
func TestAccessTokenGrant_AReplayEndsItsAccessTokens(t *testing.T) {
	data, code, httpClient, clientSecret := userTokenResponseWithScope(t, "openid", nil)
	firstAccess := data["access_token"].(string)
	firstRefresh := data["refresh_token"].(string)

	status, rotated := refreshAuthCodeGrant(t, httpClient, code, clientSecret, firstRefresh, "")
	require.Equal(t, http.StatusOK, status, "%v", rotated)
	latestAccess := rotated["access_token"].(string)
	assertUserinfoAdmits(t, latestAccess, code.User.Subject)

	status, replayed := refreshAuthCodeGrant(t, httpClient, code, clientSecret, firstRefresh, "")
	require.Equal(t, http.StatusBadRequest, status, "the replay is refused: %v", replayed)

	assertUserinfoRefusesTheToken(t, firstAccess)
	assertUserinfoRefusesTheToken(t, latestAccess)
}

// A rotation revokes the parent and inserts the child in one transaction, so the grant stays live
// and the access token issued before it goes on working beside the new one.
func TestAccessTokenGrant_ARotationKeepsTheGrantLive(t *testing.T) {
	data, code, httpClient, clientSecret := userTokenResponseWithScope(t, "openid", nil)
	firstAccess := data["access_token"].(string)
	refreshToken := data["refresh_token"].(string)

	for i := 1; i <= 2; i++ {
		status, rotated := refreshAuthCodeGrant(t, httpClient, code, clientSecret, refreshToken, "")
		require.Equal(t, http.StatusOK, status, "refresh %d: %v", i, rotated)
		refreshToken = rotated["refresh_token"].(string)
		assertUserinfoAdmits(t, rotated["access_token"].(string), code.User.Subject)
	}

	assertUserinfoAdmits(t, firstAccess, code.User.Subject)
}
