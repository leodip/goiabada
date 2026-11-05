package integration

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/leodip/goiabada/authserver/internal/fake"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// OpenID Connect Back-Channel Logout 1.0, as an app sees it (#784): a receiver on 127.0.0.1, which
// the server under test reaches on the same host, records each POST to its back-channel logout URI,
// and each case drives a real end of a session through the endpoints and reads what arrived.

// logoutReceiver is an app's back-channel logout endpoint. It answers each POST with the next
// scripted status, the last one repeated, and keeps what arrived and when.
type logoutReceiver struct {
	server   *httptest.Server
	mu       sync.Mutex
	statuses []int
	posts    []logoutPost
}

type logoutPost struct {
	at          time.Time
	contentType string
	token       string
}

func newLogoutReceiver(t *testing.T, statuses ...int) *logoutReceiver {
	t.Helper()
	rc := &logoutReceiver{statuses: statuses}
	rc.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		rc.mu.Lock()
		rc.posts = append(rc.posts, logoutPost{at: time.Now(), contentType: r.Header.Get("Content-Type"),
			token: r.PostForm.Get("logout_token")})
		status := http.StatusOK
		if len(rc.statuses) > 0 {
			status = rc.statuses[0]
			if len(rc.statuses) > 1 {
				rc.statuses = rc.statuses[1:]
			}
		}
		rc.mu.Unlock()
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(status)
	}))
	t.Cleanup(rc.server.Close)
	return rc
}

// uri is the receiver's back-channel logout URI, plain http on loopback, which an administrator
// may register for a confidential client.
func (rc *logoutReceiver) uri() string {
	return rc.server.URL + "/backchannel-logout"
}

func (rc *logoutReceiver) received() []logoutPost {
	rc.mu.Lock()
	defer rc.mu.Unlock()
	return append([]logoutPost(nil), rc.posts...)
}

// waitFor waits up to timeout for n POSTs to have arrived and answers what did.
func (rc *logoutReceiver) waitFor(t *testing.T, n int, timeout time.Duration) []logoutPost {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if posts := rc.received(); len(posts) >= n {
			return posts
		}
		time.Sleep(50 * time.Millisecond)
	}
	posts := rc.received()
	require.GreaterOrEqual(t, len(posts), n, "the app was not told in time")
	return posts
}

// backchannelClient creates a confidential client with the authorization code flow, and sets its
// back-channel logout URI through the Admin API, as an administrator would.
func backchannelClient(t *testing.T, adminToken, uri string) *record.Client {
	t.Helper()
	client := newBackchannelLogoutClient(t, "bcl-", false, "", false)
	if uri != "" {
		status, body, _ := saveBackchannelLogout(t, adminToken, client.Id, backchannelLogoutBody(uri, false))
		require.Equal(t, http.StatusOK, status, "%v", body)
	}
	return client
}

// onSession records that the session served the client, as a sign-in through it does.
func onSession(t *testing.T, session *record.UserSession, client *record.Client) {
	t.Helper()
	now := time.Now().UTC()
	require.NoError(t, database.CreateUserSessionClient(context.Background(), nil, &record.UserSessionClient{
		UserSessionId: session.Id, ClientId: client.Id, Started: now, LastAccessed: now,
	}))
}

// verifiedLogoutToken checks the token's signature against the key /certs publishes under its kid,
// and answers its header and claims.
func verifiedLogoutToken(t *testing.T, raw string) (map[string]interface{}, jwt.MapClaims) {
	t.Helper()

	resp, err := http.Get(appConfig.AuthServer.BaseURL + "/certs")
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	var set struct {
		Keys []struct {
			Kid string `json:"kid"`
			N   string `json:"n"`
			E   string `json:"e"`
		} `json:"keys"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&set))

	claims := jwt.MapClaims{}
	token, err := jwt.ParseWithClaims(raw, claims, func(token *jwt.Token) (interface{}, error) {
		kid, _ := token.Header["kid"].(string)
		for _, key := range set.Keys {
			if key.Kid != kid {
				continue
			}
			n, decodeErr := base64.RawURLEncoding.DecodeString(key.N)
			require.NoError(t, decodeErr)
			e, decodeErr := base64.RawURLEncoding.DecodeString(key.E)
			require.NoError(t, decodeErr)
			return &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: int(new(big.Int).SetBytes(e).Int64())}, nil
		}
		t.Fatalf("no key in /certs has kid %q", kid)
		return nil, nil
	}, jwt.WithValidMethods([]string{"RS256"}))
	require.NoError(t, err, "the logout token must verify against /certs")
	return token.Header, claims
}

// assertLogoutToken holds what arrived to Back-Channel Logout 1.0 section 2.4 and #784 decision 4,
// for a token about the session sid of the user subject, or about every session of the user when
// sid is empty, to the client clientIdentifier.
func assertLogoutToken(t *testing.T, got logoutPost, clientIdentifier, subject, sid string) jwt.MapClaims {
	t.Helper()

	assert.Equal(t, "application/x-www-form-urlencoded", got.contentType)
	header, claims := verifiedLogoutToken(t, got.token)
	assert.Equal(t, "logout+jwt", header["typ"])
	assert.Equal(t, "RS256", header["alg"])

	settings, err := database.GetSettingsById(context.Background(), nil, 1)
	require.NoError(t, err)
	assert.Equal(t, settings.Issuer, claims["iss"])
	assert.Equal(t, clientIdentifier, claims["aud"])
	assert.Equal(t, subject, claims["sub"])
	if sid == "" {
		assert.NotContains(t, claims, "sid", "a token about every session of the user carries sub alone")
	} else {
		assert.Equal(t, sid, claims["sid"])
	}
	assert.Equal(t, map[string]interface{}{"http://schemas.openid.net/event/backchannel-logout": map[string]interface{}{}},
		claims["events"])
	assert.NotContains(t, claims, "nonce")
	assert.NotEmpty(t, claims["jti"])

	iat, _ := claims["iat"].(float64)
	exp, _ := claims["exp"].(float64)
	assert.InDelta(t, float64(time.Now().Unix()), iat, 30)
	assert.InDelta(t, 120, exp-iat, 0, "a logout token lives two minutes")
	return claims
}

// sentLogoutTokenRow waits for the sent_logout_token row the request requestId left, which is
// written once its delivery has finished, and answers its details.
func sentLogoutTokenRow(t *testing.T, requestId string, timeout time.Duration) (record.AuditLog, map[string]interface{}) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		rows, total, err := database.GetAuditLogsPaginated(context.Background(), nil, 1, 10,
			record.AuditLogFilter{AuditEvent: "sent_logout_token", RequestId: requestId})
		require.NoError(t, err)
		if total > 0 || time.Now().After(deadline) {
			require.Equal(t, 1, total, "one sent_logout_token row for request %s", requestId)
			var details map[string]interface{}
			require.NoError(t, json.Unmarshal([]byte(rows[0].Details), &details))
			return rows[0], details
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// accountSessionUser is a user holding an account token and one live session served by two
// clients: one with a back-channel logout URI pointing at rc, and one with none. A third client,
// with a URI, is not on the session.
func accountSessionUser(t *testing.T, rc *logoutReceiver) (string, *record.User, *record.UserSession, *record.Client, *logoutReceiver) {
	t.Helper()
	adminToken, adminClient := createAdminClientWithToken(t)
	t.Cleanup(func() { _ = database.DeleteClient(context.Background(), nil, adminClient.Id) })

	accessToken, user := getUserAccessTokenWithAccountScope(t)
	session := createTestUserSession(t, user.Id, fake.UUID())

	told := backchannelClient(t, adminToken, rc.uri())
	onSession(t, session, told)
	onSession(t, session, backchannelClient(t, adminToken, ""))
	elsewhere := newLogoutReceiver(t)
	backchannelClient(t, adminToken, elsewhere.uri())

	return accessToken, user, session, told, elsewhere
}

// TestBackchannelLogout_AUserEndingTheirSessionTellsItsApps: the user ends one of their sessions
// under Account, and the app on it with a back-channel logout URI gets one logout token naming the
// user and the session. The app without a URI and the app not on the session get nothing.
func TestBackchannelLogout_AUserEndingTheirSessionTellsItsApps(t *testing.T) {
	requireDatabaseAuditLogs(t)
	rc := newLogoutReceiver(t, http.StatusOK)
	accessToken, user, session, told, elsewhere := accountSessionUser(t, rc)
	deliveredBefore := sampleValue(t, scrapeMetrics(t), `goiabada_backchannel_logout_deliveries_total{outcome="delivered"}`)

	resp, requestId := sendAdminRequest(t, accessToken, http.MethodDelete,
		"/api/v1/account/sessions/"+strconv.FormatInt(session.Id, 10), nil)
	_ = resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	posts := rc.waitFor(t, 1, 10*time.Second)
	require.Len(t, posts, 1)
	claims := assertLogoutToken(t, posts[0], told.ClientIdentifier, user.Subject, session.SessionIdentifier)

	row, details := sentLogoutTokenRow(t, requestId, 10*time.Second)
	assert.Equal(t, map[string]interface{}{
		"client_id":          float64(told.Id),
		"user_id":            float64(user.Id),
		"session_identifier": session.SessionIdentifier,
		"jti":                claims["jti"],
		"outcome":            "delivered",
		"attempts":           float64(1),
	}, details)
	assert.Equal(t, user.Id, row.UserId.Int64, "the row is found by the user filter")

	assert.InDelta(t, deliveredBefore+1,
		sampleValue(t, scrapeMetrics(t), `goiabada_backchannel_logout_deliveries_total{outcome="delivered"}`), 0)
	assert.Empty(t, elsewhere.received(), "an app not on the session is told nothing")
}

// TestBackchannelLogout_AnAdministratorEndingASessionTellsItsApps: an administrator ends the
// session, and the app answering 400 is tried once and recorded as refused.
func TestBackchannelLogout_AnAdministratorEndingASessionTellsItsApps(t *testing.T) {
	requireDatabaseAuditLogs(t)
	adminToken, adminClient := createAdminClientWithToken(t)
	t.Cleanup(func() { _ = database.DeleteClient(context.Background(), nil, adminClient.Id) })

	user := &record.User{Subject: fake.UUID(), Enabled: true, Email: uniqueEmail("bcl@admin-end.test")}
	require.NoError(t, database.CreateUser(context.Background(), nil, user))
	t.Cleanup(func() { _ = database.DeleteUser(context.Background(), nil, user.Id) })
	session := createTestUserSession(t, user.Id, fake.UUID())

	rc := newLogoutReceiver(t, http.StatusBadRequest)
	client := backchannelClient(t, adminToken, rc.uri())
	onSession(t, session, client)

	resp, requestId := sendAdminRequest(t, adminToken, http.MethodDelete,
		"/api/v1/admin/user-sessions/"+strconv.FormatInt(session.Id, 10), nil)
	_ = resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	posts := rc.waitFor(t, 1, 10*time.Second)
	assertLogoutToken(t, posts[0], client.ClientIdentifier, user.Subject, session.SessionIdentifier)

	// The row is written when the delivery finishes, so one attempt on it is a delivery that was not
	// retried.
	_, details := sentLogoutTokenRow(t, requestId, 10*time.Second)
	assert.Equal(t, "refused", details["outcome"])
	assert.InDelta(t, 1, details["attempts"], 0)
	assert.Len(t, rc.received(), 1)
}

// TestBackchannelLogout_AnAppThatFailsIsTriedAgain: a 503 is retried about 15 seconds later with the
// same token, and the delivery that then succeeds is recorded with both attempts.
func TestBackchannelLogout_AnAppThatFailsIsTriedAgain(t *testing.T) {
	requireDatabaseAuditLogs(t)
	rc := newLogoutReceiver(t, http.StatusServiceUnavailable, http.StatusOK)
	accessToken, _, session, _, _ := accountSessionUser(t, rc)

	resp, requestId := sendAdminRequest(t, accessToken, http.MethodDelete,
		"/api/v1/account/sessions/"+strconv.FormatInt(session.Id, 10), nil)
	_ = resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	posts := rc.waitFor(t, 2, 30*time.Second)
	require.Len(t, posts, 2)
	assert.Equal(t, posts[0].token, posts[1].token, "every attempt resends the same token")
	gap := posts[1].at.Sub(posts[0].at)
	assert.GreaterOrEqual(t, gap, 13*time.Second)
	assert.LessOrEqual(t, gap, 18*time.Second)

	_, details := sentLogoutTokenRow(t, requestId, 10*time.Second)
	assert.Equal(t, "delivered", details["outcome"])
	assert.InDelta(t, 2, details["attempts"], 0)
}

// TestBackchannelLogout_AnotherUserSigningInOnTheBrowserTellsThePreviousUsersApps: the browser
// changes hands, and the app the previous user's session served is told that session ended.
func TestBackchannelLogout_AnotherUserSigningInOnTheBrowserTellsThePreviousUsersApps(t *testing.T) {
	b := createCrossUserBrowser(t, record.AcrLevel1, record.AcrLevel1)
	rc := newLogoutReceiver(t, http.StatusOK)
	require.NoError(t, database.SetClientBackchannelLogout(context.Background(), nil, b.client.Id, rc.uri(), false))

	signInWithPassword(t, b.jar, crossUserAuthorizeUrl(b, "&prompt=login"), b.userB.Email, b.passwordB, false, "")

	posts := rc.waitFor(t, 1, 10*time.Second)
	require.Len(t, posts, 1)
	assertLogoutToken(t, posts[0], b.client.ClientIdentifier, b.userA.Subject, b.sessionA.SessionIdentifier)
}

// TestBackchannelLogout_AnExpiredSessionEndedByAHandoverTellsNobody: a session past its idle
// timeout or maximum lifetime sends nothing when another user's sign-in ends it (#784 decision 1).
func TestBackchannelLogout_AnExpiredSessionEndedByAHandoverTellsNobody(t *testing.T) {
	for _, dead := range deadSessionCases(t) {
		t.Run(dead.name, func(t *testing.T) {
			b := createCrossUserBrowser(t, record.AcrLevel1, record.AcrLevel1)
			rc := newLogoutReceiver(t, http.StatusOK)
			require.NoError(t, database.SetClientBackchannelLogout(context.Background(), nil, b.client.Id, rc.uri(), false))
			b.sessionA.Started = dead.started
			b.sessionA.LastAccessed = dead.lastAccessed
			require.NoError(t, database.UpdateUserSession(context.Background(), nil, b.sessionA))

			signInWithPassword(t, b.jar, crossUserAuthorizeUrl(b, ""), b.userB.Email, b.passwordB, false, "")

			ended, err := database.GetUserSessionBySessionIdentifier(context.Background(), nil, b.sessionA.SessionIdentifier)
			require.NoError(t, err)
			require.Nil(t, ended, "the handover ended the expired session")
			time.Sleep(2 * time.Second)
			assert.Empty(t, rc.received())
		})
	}
}
