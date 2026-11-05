package main

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/leodip/goiabada/authserver/internal/audit"
	"github.com/leodip/goiabada/authserver/internal/data/sqlitedb"
	"github.com/leodip/goiabada/authserver/internal/encryption"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/authserver/internal/recovery"
	"github.com/leodip/goiabada/authserver/internal/signingkeys"
)

// The recover command tells the recovered user's apps that the user was signed out, after its
// commit, and says on the console what it is doing as it does it (#784 decision 11). Each test
// drives the command against its own SQLite database and a receiver the test owns, the app's
// back-channel logout endpoint, and reads what arrived there, what the command printed and its
// exit status.

// recoverTestCipher is the data cipher the test databases' signing key is sealed under.
var recoverTestCipher = func() *encryption.DataCipher {
	cipher, err := encryption.NewDataCipher([]byte("recover-test-data-key-0123456789"))
	if err != nil {
		panic(err)
	}
	return cipher
}()

// recoverTestKey is one signing key shared by every test database, so each does not wait for a key
// of its own to be generated.
var recoverTestKey struct {
	once    sync.Once
	keyPair *record.KeyPair
	err     error
}

// recoverTestKeyPair answers an unsaved copy of the shared signing key, in the current state.
func recoverTestKeyPair(t *testing.T) *record.KeyPair {
	t.Helper()
	recoverTestKey.once.Do(func() {
		recoverTestKey.keyPair, recoverTestKey.err = signingkeys.NewKeyPair(recoverTestCipher, record.KeyStateCurrent, 2048)
	})
	require.NoError(t, recoverTestKey.err)
	keyPair := *recoverTestKey.keyPair
	return &keyPair
}

// recoverTestDataKey is the data key the command is run with: the one the signing key is sealed
// under.
func recoverTestDataKey(*testing.T) recoverDataKey {
	return recoverDataKey{cipher: recoverTestCipher}
}

// logoutPost is one POST that arrived at the receiver.
type logoutPost struct {
	path   string
	header map[string]interface{}
	claims jwt.MapClaims
	// sessionsLeft is how many sessions the user still had when the POST arrived.
	sessionsLeft int
}

// logoutReceiver is the apps' back-channel logout endpoints: each path answers its scripted status,
// 200 when none, and every POST is kept with its token, verified against the database's signing key.
type logoutReceiver struct {
	t        *testing.T
	db       *sqlitedb.Database
	userId   int64
	server   *httptest.Server
	statuses map[string]int
	mu       sync.Mutex
	posts    []logoutPost
}

func newLogoutReceiver(t *testing.T, db *sqlitedb.Database, userId int64, statuses map[string]int) *logoutReceiver {
	t.Helper()
	rc := &logoutReceiver{t: t, db: db, userId: userId, statuses: statuses}
	rc.server = httptest.NewServer(http.HandlerFunc(rc.serve))
	t.Cleanup(rc.server.Close)
	return rc
}

func (rc *logoutReceiver) serve(w http.ResponseWriter, r *http.Request) {
	keyPair := recoverTestKeyPair(rc.t)
	public, err := jwt.ParseRSAPublicKeyFromPEM(keyPair.PublicKeyPEM)
	assert.NoError(rc.t, err)
	assert.NoError(rc.t, r.ParseForm())
	claims := jwt.MapClaims{}
	token, err := jwt.ParseWithClaims(r.PostForm.Get("logout_token"), claims,
		func(*jwt.Token) (interface{}, error) { return public, nil }, jwt.WithValidMethods([]string{"RS256"}))
	assert.NoError(rc.t, err, "the logout token verifies against the signing key")
	header := map[string]interface{}{}
	if token != nil {
		header = token.Header
	}
	sessions, err := rc.db.GetUserSessionsByUserId(context.Background(), nil, rc.userId)
	assert.NoError(rc.t, err)

	rc.mu.Lock()
	rc.posts = append(rc.posts, logoutPost{path: r.URL.Path, header: header, claims: claims, sessionsLeft: len(sessions)})
	status, scripted := rc.statuses[r.URL.Path]
	rc.mu.Unlock()
	if !scripted {
		status = http.StatusOK
	}
	w.WriteHeader(status)
}

// received answers the POSTs that arrived at path.
func (rc *logoutReceiver) received(path string) []logoutPost {
	rc.mu.Lock()
	defer rc.mu.Unlock()
	var out []logoutPost
	for _, p := range rc.posts {
		if p.path == path {
			out = append(out, p)
		}
	}
	return out
}

func (rc *logoutReceiver) all() []logoutPost {
	rc.mu.Lock()
	defer rc.mu.Unlock()
	return append([]logoutPost(nil), rc.posts...)
}

// recoverUser is the seeded user, as the database holds them.
func recoverUser(t *testing.T, db *sqlitedb.Database) *record.User {
	t.Helper()
	user, err := db.GetUserByEmail(context.Background(), nil, "admin@example.com")
	require.NoError(t, err)
	require.NotNil(t, user)
	return user
}

// seedLogoutClient stores an administrator's confidential client with a sign-in flow and the
// back-channel logout settings given; an empty uri registers none.
func seedLogoutClient(t *testing.T, db *sqlitedb.Database, identifier, uri string, sessionRequired bool) *record.Client {
	t.Helper()
	client := &record.Client{
		ClientIdentifier:                 identifier,
		Description:                      identifier,
		Enabled:                          true,
		AuthorizationCodeEnabled:         true,
		TokenExpirationInSeconds:         300,
		DefaultAcrLevel:                  record.AcrLevel1,
		BackchannelLogoutURI:             uri,
		BackchannelLogoutSessionRequired: sessionRequired,
	}
	require.NoError(t, db.CreateClient(context.Background(), nil, client))
	return client
}

// seedLogoutSession stores a session of the user, last used lastUsedAgo before now, that served
// each of clients.
func seedLogoutSession(t *testing.T, db *sqlitedb.Database, userId int64, sid string, lastUsedAgo time.Duration,
	clients ...*record.Client) {
	t.Helper()
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Microsecond)
	session := &record.UserSession{
		SessionIdentifier: sid,
		Started:           now.Add(-lastUsedAgo),
		LastAccessed:      now.Add(-lastUsedAgo),
		AuthMethods:       "pwd",
		AcrLevel:          record.AcrLevel1,
		AuthTime:          now.Add(-lastUsedAgo),
		PasswordAuthTime:  now.Add(-lastUsedAgo),
		IpAddress:         "192.0.2.10",
		DeviceType:        "desktop",
		UserId:            userId,
	}
	require.NoError(t, db.CreateUserSession(ctx, nil, session))
	for _, client := range clients {
		require.NoError(t, db.CreateUserSessionClient(ctx, nil, &record.UserSessionClient{
			UserSessionId: session.Id,
			ClientId:      client.Id,
			Started:       session.Started,
			LastAccessed:  session.LastAccessed,
		}))
	}
}

// outputLines answers stdout's lines, in order.
func outputLines(stdout string) []string {
	return strings.Split(strings.TrimRight(stdout, "\n"), "\n")
}

// lineIndex answers the position of line among lines, or -1.
func lineIndex(lines []string, line string) int {
	for i, l := range lines {
		if l == line {
			return i
		}
	}
	return -1
}

// TestRecover_TellsEveryAppThatKnewTheUser: a recovery is a user-wide end (#784 decision 3), and
// once it has committed the command tells each app that knew the user, waiting for every delivery
// (decision 11). An app not requiring sid gets one token naming sub alone, whichever of the user's
// sessions it was on, an expired one included. An app requiring sid gets a sub+sid token for each
// valid session it was on, and none for the expired one. An app with no back-channel logout URI is
// sent nothing. The command says it is telling four apps, prints one line per app as each finishes,
// one for the app told twice, and a last line counting the apps told and not told. An app refusing
// the token does not fail the recovery: the exit status stays 0.
func TestRecover_TellsEveryAppThatKnewTheUser(t *testing.T) {
	db, _ := newRecoverDatabase(t)
	user := recoverUser(t, db)
	rc := newLogoutReceiver(t, db, user.Id, map[string]int{"/refuses": http.StatusBadRequest})

	subOnly := seedLogoutClient(t, db, "app-sub-only", rc.server.URL+"/sub-only", false)
	expiredOnly := seedLogoutClient(t, db, "app-expired-only", rc.server.URL+"/expired-only", false)
	requiresSid := seedLogoutClient(t, db, "app-requires-sid", rc.server.URL+"/requires-sid", true)
	refuses := seedLogoutClient(t, db, "app-refuses", rc.server.URL+"/refuses", false)
	withoutURI := seedLogoutClient(t, db, "app-without-uri", "", false)

	seedLogoutSession(t, db, user.Id, "sid-valid-1", time.Minute, subOnly, requiresSid, refuses, withoutURI)
	// Past the seeded idle timeout of two hours.
	seedLogoutSession(t, db, user.Id, "sid-expired", 3*time.Hour, subOnly, expiredOnly, requiresSid)
	seedLogoutSession(t, db, user.Id, "sid-valid-2", 2*time.Minute, requiresSid)

	recorder := &recoverAuditRecorder{}
	code, stdout, stderr := runRecoverOn(t, db, recorder, recoverInvocation{
		email: "admin@example.com", grantManage: true,
	})

	assert.Equal(t, migrateExitOK, code, "a delivery that is refused does not fail the recovery: %s", stderr)

	// What each app received.
	for _, path := range []string{"/sub-only", "/expired-only", "/refuses"} {
		posts := rc.received(path)
		require.Lenf(t, posts, 1, "%s is sent one token naming sub alone", path)
		assert.Equal(t, "logout+jwt", posts[0].header["typ"])
		assert.Equal(t, "recover-subject", posts[0].claims["sub"])
		assert.NotContainsf(t, posts[0].claims, "sid", "%s's token asks it to end every session of the user", path)
		assert.Equal(t, "https://localhost:8080", posts[0].claims["iss"])
	}
	assert.Equal(t, "app-sub-only", rc.received("/sub-only")[0].claims["aud"])
	assert.Equal(t, "app-expired-only", rc.received("/expired-only")[0].claims["aud"])

	sidPosts := rc.received("/requires-sid")
	require.Len(t, sidPosts, 2, "the app requiring sid is sent one token per valid session it was on")
	var sids []interface{}
	for _, p := range sidPosts {
		assert.Equal(t, "recover-subject", p.claims["sub"], "sub is sent beside sid")
		assert.Equal(t, "app-requires-sid", p.claims["aud"])
		sids = append(sids, p.claims["sid"])
	}
	assert.ElementsMatch(t, []interface{}{"sid-valid-1", "sid-valid-2"}, sids)
	assert.Len(t, rc.all(), 5, "the app with no back-channel logout URI is sent nothing")

	// Every token was sent after the commit: the user's sessions were already gone.
	for _, p := range rc.all() {
		assert.Zerof(t, p.sessionsLeft, "the token to %s arrived after the recovery committed", p.path)
	}

	// What the command said, in order: the recovery, the line before the deliveries, one line per
	// app, and the count.
	lines := outputLines(stdout)
	recovered := lineIndex(lines, "  sessions ended: 3, refresh tokens revoked: 0, authentication generation 0 to 1")
	telling := lineIndex(lines, "telling 4 apps that the user was signed out; this can take up to about a minute "+
		"when an app does not answer")
	summary := lineIndex(lines, "apps told: 3, not told: 1")
	require.NotEqual(t, -1, recovered, stdout)
	require.NotEqual(t, -1, telling, stdout)
	require.NotEqual(t, -1, summary, stdout)
	assert.Less(t, recovered, telling, "the recovery is reported before the deliveries start")
	assert.Equal(t, len(lines)-1, summary, "the count is the last line")
	assert.ElementsMatch(t, []string{
		"  app-sub-only: delivered",
		"  app-expired-only: delivered",
		"  app-requires-sid: delivered",
		"  app-refuses: refused",
	}, lines[telling+1:summary], "one line per app, between the two")

	// Each delivery's audit event, after the recovery's own, naming the command as the actor.
	var revokedAt = -1
	sent := map[string]int{}
	for i, event := range recorder.events {
		if event == audit.EventRevokedUserAuthState {
			revokedAt = i
		}
		if event != audit.EventSentLogoutToken {
			continue
		}
		assert.Greater(t, i, revokedAt, "the deliveries are recorded after the recovery")
		details := recorder.details[i]
		assert.Equal(t, recovery.Actor, details["command"])
		assert.Equal(t, user.Id, details["user_id"])
		sent[details["outcome"].(string)]++
	}
	assert.NotEqual(t, -1, revokedAt)
	assert.Equal(t, map[string]int{"delivered": 4, "refused": 1}, sent)
}

// TestRecover_SaysSoInOneLineWhenNoAppIsToBeTold: a user whose apps registered no back-channel
// logout URI leaves nobody to tell, and the command says so in one line and waits for nothing.
func TestRecover_SaysSoInOneLineWhenNoAppIsToBeTold(t *testing.T) {
	db, _ := newRecoverDatabase(t)
	user := recoverUser(t, db)
	withoutURI := seedLogoutClient(t, db, "app-without-uri", "", false)
	seedLogoutSession(t, db, user.Id, "sid-valid", time.Minute, withoutURI)

	code, stdout, stderr := runRecoverOn(t, db, &recoverAuditRecorder{}, recoverInvocation{
		email: "admin@example.com", grantManage: true,
	})

	assert.Equal(t, migrateExitOK, code, stderr)
	lines := outputLines(stdout)
	assert.Equal(t, "no app to tell that the user was signed out", lines[len(lines)-1], stdout)
	assert.NotContains(t, stdout, "telling")
	assert.NotContains(t, stdout, "apps told")
}

// TestRecover_TurningTurnstileOffAloneTellsNoApp: --disable-turnstile alone ends no session, so it
// sends nothing and says nothing about apps.
func TestRecover_TurningTurnstileOffAloneTellsNoApp(t *testing.T) {
	db, _ := newRecoverDatabase(t)
	user := recoverUser(t, db)
	rc := newLogoutReceiver(t, db, user.Id, nil)
	app := seedLogoutClient(t, db, "app-sub-only", rc.server.URL+"/sub-only", false)
	seedLogoutSession(t, db, user.Id, "sid-valid", time.Minute, app)

	code, stdout, stderr := runRecoverOn(t, db, &recoverAuditRecorder{}, recoverInvocation{disableTurnstile: true})

	assert.Equal(t, migrateExitOK, code, stderr)
	assert.NotContains(t, stdout, "app")
	assert.Empty(t, rc.all())
}

// TestRecover_AnUnusableDataKeyLeavesTheRecoveryAndSaysTheAppsWereNotTold: the recovery needs no
// data key, so one that is missing still recovers the user, with the exit status of the recovery.
// No logout token can be signed without it, so the command says on stderr that the app was not
// told, and why, and sends nothing.
func TestRecover_AnUnusableDataKeyLeavesTheRecoveryAndSaysTheAppsWereNotTold(t *testing.T) {
	db, _ := newRecoverDatabase(t)
	user := recoverUser(t, db)
	rc := newLogoutReceiver(t, db, user.Id, nil)
	app := seedLogoutClient(t, db, "app-sub-only", rc.server.URL+"/sub-only", false)
	seedLogoutSession(t, db, user.Id, "sid-valid", time.Minute, app)

	m, err := db.NewMigrator(context.Background(), nil)
	require.NoError(t, err)
	var out, errOut strings.Builder
	code := runRecover(context.Background(), db, m, &recoverAuditRecorder{},
		recoverInvocation{email: "admin@example.com", grantManage: true},
		recoverDataKey{err: errors.New("GOIABADA_AES_ENCRYPTION_KEY is required")}, &out, &errOut)

	assert.Equal(t, migrateExitOK, code, errOut.String())
	assert.Contains(t, out.String(), "recovered admin@example.com")
	assert.Equal(t, "unable to tell 1 app that the user was signed out, because no logout token can be "+
		"signed without the data encryption key: GOIABADA_AES_ENCRYPTION_KEY is required\n", errOut.String())
	assert.Empty(t, rc.all())
	assert.Equal(t, int64(1), recoverUser(t, db).AuthStateGeneration, "the recovery committed")
}
