package datatests

import (
	"context"
	"database/sql"
	"sync"
	"testing"
	"time"

	"github.com/leodip/goiabada/authserver/internal/data"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/authserver/internal/usersession"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The two orderings of #538, where a real database orders the writes: a bind whose sign-in is
// older than the authentication a session already holds must write nothing, and the session must
// keep what the newer sign-in left, whichever tab held the older credential.
//
// The window the issue names is inside one /auth/completed request that has loaded its context:
// tab A's request stalls before its bind's transaction opens, tab B runs a whole ceremony
// meanwhile, and tab A resumes. The session's row lock cannot help there -- tab B has already
// committed -- so the ordering rule inside the bind is what decides, and it decides on the row
// tab A's transaction then reads: an authentication older than the session's current auth_time
// writes nothing, not the level or methods a step-up would raise, not the level and methods a
// prompt=login would replace them with, and not an auth_time that moves backwards. The older
// ceremony answers ErrStaleAuthentication and /auth/completed restarts it, as it restarts a
// ceremony whose one-time code no longer stands.
//
// The stall is forced rather than hoped for: tab A's request carries a decorator whose
// RunInTransaction waits until tab B's bind has committed, so the older bind always opens its
// transaction against the row the newer sign-in already wrote. The two transactions never overlap,
// so the ordering is forced on every engine alike, SQLite's one-connection pool included.

// staleBindStaller is what one /auth/completed request is handed: the real database, with the
// bind's transaction held closed until the sign-in that is meant to complete first has
// committed. reached proves the stalled bind has entered its transaction callback before the
// other sign-in starts, so the test parks tab A where it says it does; release lets it go, and
// the test's cleanup closes it too, so a failing run never leaves the goroutine blocked.
type staleBindStaller struct {
	data.Database
	reached     chan struct{}
	reachedOnce sync.Once
	release     chan struct{}
	releaseOnce sync.Once
}

func (s *staleBindStaller) RunInTransaction(ctx context.Context, fn func(tx *sql.Tx) error) error {
	s.reachedOnce.Do(func() { close(s.reached) })
	<-s.release
	return s.Database.RunInTransaction(ctx, fn)
}

func (s *staleBindStaller) proceed() {
	s.releaseOnce.Do(func() { close(s.release) })
}

// signInOf answers what one completed sign-in hands its bind, at the instant given.
func signInOf(userId int64, methods string, level record.AcrLevel, at time.Time, passwordAt *time.Time) usersession.Authentication {
	return usersession.Authentication{
		UserId:           userId,
		AuthMethods:      methods,
		AcrLevel:         level,
		AuthTime:         &at,
		PasswordAuthTime: passwordAt,
	}
}

// An older sign-in raising the session over a newer one, the second scenario #538 names: tab A verified its code before tab B's password was
// accepted; tab A's request stalls, tab B completes a whole prompt=login at a level 1 client that
// leaves the session at level 1, pwd, and tab A resumes. The step-up's bind then opens against the
// row tab B committed: its authentication is the older one, so it writes nothing, and the session
// keeps the newer sign-in's level 1 and pwd rather than being raised to level 2 mandatory, pwd otp by an
// authentication that predates it.
func TestBindUserSession_AnOlderStepUpThatResumesAfterANewerSignInWritesNothing(t *testing.T) {
	user := createTestUser(t)
	clientA := createTestClient(t)
	clientB := createTestClient(t)
	session := createTestUserSession(t, user.Id)

	newer := time.Now().UTC().Truncate(time.Microsecond)
	older := newer.Add(-2 * time.Minute)

	stalled := &staleBindStaller{Database: database, reached: make(chan struct{}), release: make(chan struct{})}
	defer stalled.proceed()
	tabA := usersession.NewManager(nil, "", stalled, false)

	signaled := make(chan error, 1)
	go func() {
		_, err := tabA.BindUserSession(context.Background(), session.SessionIdentifier, clientA.Id,
			signInOf(user.Id, "pwd otp", record.AcrLevel2Mandatory, older, nil), false, "")
		signaled <- err
	}()

	// Park tab A inside its bind's transaction before tab B's sign-in starts.
	<-stalled.reached

	// Tab B's whole prompt=login, completing while tab A's request is stalled.
	tabB := usersession.NewManager(nil, "", database, false)
	bumped, err := tabB.BindUserSession(context.Background(), session.SessionIdentifier, clientB.Id,
		signInOf(user.Id, "pwd", record.AcrLevel1, newer, &newer), true, "")
	require.NoError(t, err)
	assert.Equal(t, record.AcrLevel1, bumped.AcrLevel)

	stalled.proceed()

	// Tab A's bind answered the ordering rule rather than raising the session over the newer
	// sign-in's authentication.
	require.ErrorIs(t, <-signaled, usersession.ErrStaleAuthentication)

	final := readStaleTestSession(t, session.SessionIdentifier)
	assert.Equal(t, record.AcrLevel1, final.AcrLevel, "the session keeps the newer sign-in's level")
	assert.Equal(t, "pwd", final.AuthMethods, "and its methods, without the code the older step-up verified")
	assert.Truef(t, final.AuthTime.Equal(newer), "auth_time is the newer password's, not the older code's: %v", final.AuthTime)
	assert.Truef(t, final.PasswordAuthTime.Equal(newer), "password_auth_time is the newer password's: %v", final.PasswordAuthTime)
}

// The same window, the other ordering, the first scenario #538 names (a step-up is lost): tab A's prompt=login accepted its password before tab B
// verified a code. Tab A resumes after tab B's step-up has left the session at level 2 mandatory, pwd otp,
// and its replace must not write the older password's level 1 and pwd over the newer
// authentication, as it would without the ordering rule.
func TestBindUserSession_AnOlderReplaceThatResumesAfterANewerStepUpWritesNothing(t *testing.T) {
	user := createTestUser(t)
	clientA := createTestClient(t)
	clientB := createTestClient(t)
	session := createTestUserSession(t, user.Id)

	newer := time.Now().UTC().Truncate(time.Microsecond)
	older := newer.Add(-2 * time.Minute)

	stalled := &staleBindStaller{Database: database, reached: make(chan struct{}), release: make(chan struct{})}
	defer stalled.proceed()
	tabA := usersession.NewManager(nil, "", stalled, false)

	signaled := make(chan error, 1)
	go func() {
		_, err := tabA.BindUserSession(context.Background(), session.SessionIdentifier, clientA.Id,
			signInOf(user.Id, "pwd", record.AcrLevel1, older, &older), true, "")
		signaled <- err
	}()

	// Park tab A inside its bind's transaction before tab B's step-up starts.
	<-stalled.reached

	// Tab B's whole step-up, completing while tab A's request is stalled.
	tabB := usersession.NewManager(nil, "", database, false)
	bumped, err := tabB.BindUserSession(context.Background(), session.SessionIdentifier, clientB.Id,
		signInOf(user.Id, "pwd otp", record.AcrLevel2Mandatory, newer, nil), false, "")
	require.NoError(t, err)
	assert.Equal(t, record.AcrLevel2Mandatory, bumped.AcrLevel)

	stalled.proceed()

	require.ErrorIs(t, <-signaled, usersession.ErrStaleAuthentication)

	final := readStaleTestSession(t, session.SessionIdentifier)
	assert.Equal(t, record.AcrLevel2Mandatory, final.AcrLevel, "the session keeps the newer step-up's level")
	assert.Equal(t, "pwd otp", final.AuthMethods, "and its methods")
	assert.Truef(t, final.AuthTime.Equal(newer), "auth_time is the newer code's, not the older password's: %v", final.AuthTime)
}

// The rule's scope: it refuses an older sign-in, never a newer one. Here the older bind commits
// first -- against a row holding an older authentication still -- and the newer sign-in's bind
// runs after it, so the newer one writes and the session describes it, as it did before the rule.
// Both binds succeed; a rule that refused the newer arrival would break every step-up that follows
// a prompt=login, which is the shape the equal-instant case below pins from the other side.
func TestBindUserSession_TheNewerSignInWinsWhicheverBindRunsSecond(t *testing.T) {
	newer := time.Now().UTC().Truncate(time.Microsecond)
	older := newer.Add(-2 * time.Minute)

	for _, tc := range []struct {
		name       string
		olderArm   string
		newerArm   string
		newMethods string
		newLevel   record.AcrLevel
	}{
		{"the older step-up commits first, the newer prompt=login writes over it",
			"step-up", "replace", "pwd", record.AcrLevel1},
		{"the older replace commits first, the newer step-up raises over it",
			"replace", "step-up", "pwd otp", record.AcrLevel2Mandatory},
	} {
		t.Run(tc.name, func(t *testing.T) {
			user := createTestUser(t)
			clientA := createTestClient(t)
			clientB := createTestClient(t)
			session := createTestUserSession(t, user.Id)

			// The row holds an authentication older than both sign-ins, so the older bind
			// commits: it is the newer of the pair the row knows about when it runs.
			seeded := older.Add(-5 * time.Minute)
			session.AcrLevel = record.AcrLevel1
			session.AuthMethods = "pwd"
			session.AuthTime = seeded
			session.PasswordAuthTime = seeded
			require.NoError(t, database.UpdateUserSession(context.Background(), nil, session))

			olderAuth := signInOf(user.Id, "pwd otp", record.AcrLevel2Mandatory, older, nil)
			olderReplace := false
			if tc.olderArm == "replace" {
				olderAuth = signInOf(user.Id, "pwd", record.AcrLevel1, older, &older)
				olderReplace = true
			}

			newerAuth := signInOf(user.Id, tc.newMethods, tc.newLevel, newer, nil)
			newerReplace := false
			if tc.newerArm == "replace" {
				newerAuth.PasswordAuthTime = &newer
				newerReplace = true
			}

			_, err := usersession.NewManager(nil, "", database, false).
				BindUserSession(context.Background(), session.SessionIdentifier, clientA.Id, olderAuth, olderReplace, "")
			require.NoError(t, err, "the older bind commits first, before the newer sign-in exists")

			_, err = usersession.NewManager(nil, "", database, false).
				BindUserSession(context.Background(), session.SessionIdentifier, clientB.Id, newerAuth, newerReplace, "")
			require.NoError(t, err, "the newer sign-in takes the session")

			final := readStaleTestSession(t, session.SessionIdentifier)
			assert.Equal(t, tc.newLevel, final.AcrLevel, "the newer sign-in's level is what the session holds")
			assert.Equal(t, tc.newMethods, final.AuthMethods, "and its methods")
			assert.Truef(t, final.AuthTime.Equal(newer), "auth_time is the newer sign-in's: %v", final.AuthTime)
		})
	}
}

// The ordering rule refuses only the older sign-in of a pair, never a current one: a bind whose
// instant equals the session's own auth_time is a retry of the sign-in that holds it, or the
// instant the password handler recorded and the bind reads again, and a newer one writes as it
// always did. The equal-instant case is the one a refusal would break sign-ins with.
func TestBindUserSession_CurrentAndNewerBindsAreNotRefused(t *testing.T) {
	user := createTestUser(t)
	client := createTestClient(t)
	session := createTestUserSession(t, user.Id)

	held := time.Now().UTC().Truncate(time.Microsecond)
	session.AcrLevel = record.AcrLevel1
	session.AuthMethods = "pwd"
	session.AuthTime = held
	session.PasswordAuthTime = held
	require.NoError(t, database.UpdateUserSession(context.Background(), nil, session))

	manager := usersession.NewManager(nil, "", database, false)

	at := held
	_, err := manager.BindUserSession(context.Background(), session.SessionIdentifier, client.Id,
		signInOf(user.Id, "pwd", record.AcrLevel1, at, &at), true, "")
	require.NoError(t, err, "a bind whose instant is the session's own auth_time is current, not stale")

	newer := held.Add(time.Minute)
	raised, err := manager.BindUserSession(context.Background(), session.SessionIdentifier, client.Id,
		signInOf(user.Id, "pwd otp", record.AcrLevel2Mandatory, newer, nil), false, "")
	require.NoError(t, err, "a newer bind writes as it always did")
	assert.Equal(t, record.AcrLevel2Mandatory, raised.AcrLevel)
	assert.Equal(t, "pwd otp", raised.AuthMethods)

	final := readStaleTestSession(t, session.SessionIdentifier)
	assert.Truef(t, final.AuthTime.Equal(newer), "auth_time moved to the newer credential's instant: %v", final.AuthTime)
}

// readStaleTestSession answers the session row as the engine holds it.
func readStaleTestSession(t *testing.T, sessionIdentifier string) *record.UserSession {
	t.Helper()
	session, err := database.GetUserSessionBySessionIdentifier(context.Background(), nil, sessionIdentifier)
	require.NoError(t, err)
	require.NotNil(t, session)
	return session
}

// The SSO case of #538, which enters no credential of its own: a ceremony that adopted the
// session still writes an older authentication onto it when it resumes, because the methods it
// merges back and the level it raises the session to were copied from the session as it stood
// when /auth/authorize adopted it. Tab A is such a ceremony, stalled at its bind; tab B completes
// a whole prompt=login at a level 1 client, which leaves the session at level 1, pwd; tab A
// resumes and would merge otp back in and raise the session over the newer sign-in. The adopted
// instant no longer matches the row the bind locks, so the bind writes nothing: it answers
// ErrStaleAuthentication and the session keeps the newer sign-in's level, methods and auth_time.
func TestBindUserSession_AnSSOBindWhoseAdoptedSessionWasReplacedWritesNothing(t *testing.T) {
	user := createTestUser(t)
	clientA := createTestClient(t)
	clientB := createTestClient(t)
	session := createTestUserSession(t, user.Id)

	// The session as the ceremony adopted it: level 2, pwd otp, with the auth_time tab A's
	// ceremony copied at /auth/authorize.
	seed := usersession.NewManager(nil, "", database, false)
	// Newer than the row createTestUserSession stamped, so the seed bind that writes the
	// adopted state is current rather than stale against it.
	adopted := time.Now().UTC().Truncate(time.Microsecond)
	_, err := seed.BindUserSession(context.Background(), session.SessionIdentifier, clientA.Id,
		signInOf(user.Id, "pwd otp", record.AcrLevel2Mandatory, adopted, &adopted), true, "")
	require.NoError(t, err)

	newer := time.Now().UTC().Truncate(time.Microsecond)

	stalled := &staleBindStaller{Database: database, reached: make(chan struct{}), release: make(chan struct{})}
	defer stalled.proceed()
	tabA := usersession.NewManager(nil, "", stalled, false)

	signaled := make(chan error, 1)
	go func() {
		// The SSO bind: the methods and level the ceremony adopted, and the instant it adopted
		// them at, entering no credential of its own.
		_, bindErr := tabA.BindUserSession(context.Background(), session.SessionIdentifier, clientA.Id,
			usersession.Authentication{UserId: user.Id, AuthMethods: "pwd otp", AcrLevel: record.AcrLevel2Mandatory,
				AdoptedAuthTime: &adopted}, false, "")
		signaled <- bindErr
	}()

	// Park tab A inside its bind's transaction before tab B's sign-in starts.
	<-stalled.reached

	// Tab B's whole prompt=login, completing while tab A's request is stalled.
	tabB := usersession.NewManager(nil, "", database, false)
	bumped, err := tabB.BindUserSession(context.Background(), session.SessionIdentifier, clientB.Id,
		signInOf(user.Id, "pwd", record.AcrLevel1, newer, &newer), true, "")
	require.NoError(t, err)
	assert.Equal(t, record.AcrLevel1, bumped.AcrLevel)

	stalled.proceed()

	// Tab A's bind answered the ordering rule rather than merging the adopted methods back
	// over the newer sign-in.
	require.ErrorIs(t, <-signaled, usersession.ErrStaleAuthentication)

	final := readStaleTestSession(t, session.SessionIdentifier)
	assert.Equal(t, record.AcrLevel1, final.AcrLevel, "the session keeps the newer sign-in's level")
	assert.Equal(t, "pwd", final.AuthMethods, "and its methods, without the otp the SSO ceremony would merge back")
	assert.Truef(t, final.AuthTime.Equal(newer), "auth_time is the newer password's, not the adopted instant: %v", final.AuthTime)
}
