package datatests

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	"github.com/leodip/goiabada/authserver/internal/models"
	"github.com/leodip/goiabada/authserver/internal/testutil/fake"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A cancelled context against a real engine, seam 2 of #386.
//
// The unit tier owns RunInTransaction's loop -- how many attempts, which exit, which error --
// against a scripted driver. What only a real engine and a real driver can answer is whether the
// context reaches them at all, which is the whole claim the acceptance criterion makes, and it is
// exactly the claim a scripted driver cannot support: the script is this package's own code and
// would honour a context the shipped driver ignores.
//
// Two of the three cases run on all four engines. The third is SQLite's and says so.

// cancelled returns a context that is already over, which is the only cancellation every engine
// and every driver answers identically: database/sql refuses the call before the driver is
// reached at all (probe/cancel.out).
func cancelled() context.Context {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	return ctx
}

func TestBeginTransaction_RefusesAnAlreadyCancelledContext(t *testing.T) {
	tx, err := database.BeginTransaction(cancelled())

	require.Error(t, err, "a cancelled caller must not be given a transaction")
	assert.ErrorIs(t, err, context.Canceled, "and the reason must be matchable, not a sentence")
	assert.Nil(t, tx, "nothing is returned to roll back")
}

func TestRunInTransaction_WithACancelledContextNeverRunsTheBody(t *testing.T) {
	ran := 0

	err := database.RunInTransaction(cancelled(), func(tx *sql.Tx) error {
		ran++
		return nil
	})

	require.Error(t, err)
	assert.ErrorIs(t, err, context.Canceled)
	assert.Zero(t, ran, "the body never ran, so nothing was written and nothing needs undoing")
}

// TestBeginTransaction_OnSqliteABlockedOpenReturnsOnItsDeadline is the fact neither #386 nor #413
// states, and the reason decision 9 records it: on SQLite the pool is one connection, so a second
// transaction opened while the first is held waits for that connection. Without a context it waits
// for ever -- probe/cancel.out measured a plain Query still blocked after two seconds -- and that
// unbounded wait is what #413's five nil-transaction reads produced: a stuck goroutine, not an
// error. With a context the wait ends at the deadline and the caller gets something it can answer
// a request with.
//
// It does not close #413. The read still escapes the transaction and still answers from before its
// writes on the other three engines; this only removes the hang.
//
// SQLite alone, and not as a convenience: the other three engines have pools of more than one
// connection, so there is nothing for a second open to block on and the case would measure
// nothing at all there.
func TestBeginTransaction_OnSqliteABlockedOpenReturnsOnItsDeadline(t *testing.T) {
	if dbType() != "sqlite" && dbType() != "" {
		t.Skip("the single-connection pool is SQLite's; on the other engines a second open has nothing to wait for")
	}

	held, err := database.BeginTransaction(context.Background())
	require.NoError(t, err, "the holder takes the only connection")
	defer func() { _ = database.RollbackTransaction(held) }()

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()

	// THE OPEN RUNS ON ITS OWN GOROUTINE, and the case has a ceiling of its own, because the
	// failure being guarded against is a wait that never ends. Called inline, a BeginTransaction
	// that dropped the context would block this test until the whole tier's timeout fired --
	// measured at ten minutes while mutating exactly that. A regression should cost five seconds
	// and name itself.
	//
	// The gaveUp arm is the other half of that, and is not ceremony. On the failing path the
	// abandoned open eventually gets the connection anyway, once this test's own holder is
	// rolled back on the way out; a transaction nobody rolls back would then hold SQLite's only
	// connection for the rest of the package and every later test would fail on the tier's
	// timeout instead of on this one line.
	type opened struct {
		tx  *sql.Tx
		err error
	}
	answered := make(chan opened)
	gaveUp := make(chan struct{})
	started := time.Now()
	go func() {
		tx, err := database.BeginTransaction(ctx)
		select {
		case answered <- opened{tx: tx, err: err}:
		case <-gaveUp:
			if tx != nil {
				_ = database.RollbackTransaction(tx)
			}
		}
	}()

	var result opened
	select {
	case result = <-answered:
	case <-time.After(5 * time.Second):
		close(gaveUp)
		t.Fatal("the second open was still blocked five seconds after a 300ms deadline: the context is not reaching the pool")
	}

	require.Error(t, result.err, "the second open cannot succeed while the only connection is held")
	assert.True(t, errors.Is(result.err, context.DeadlineExceeded),
		"the deadline is what ended the wait, and it must be matchable: got %v", result.err)
	assert.Nil(t, result.tx)
	assert.Less(t, time.Since(started), 5*time.Second)
}

// The three cases above reach BeginTx. The three below reach the statements themselves, which is
// the half of seam 2 that stage 5 adds: the 57 identity methods now carry the caller's context
// down to QuerySql and ExecSql, and nothing but a real driver says whether it arrives.
//
// They run on all four engines. An already-cancelled context is the one cancellation every
// driver answers identically, because database/sql refuses the call before the driver is reached
// at all (probe/cancel.out), and that is exactly the claim being made: the context is consulted,
// not carried and dropped.

func TestGetUserById_RefusesAnAlreadyCancelledContext(t *testing.T) {
	user := createTestUser(t)

	got, err := database.GetUserById(cancelled(), nil, user.Id)

	require.Error(t, err, "a read must not be issued on behalf of a caller that is already gone")
	assert.ErrorIs(t, err, context.Canceled, "and the reason must be matchable, not a sentence")
	assert.Nil(t, got, "no row is returned alongside the refusal")
}

// The write half, and the assertion that matters is the second one: a refused statement must
// leave the table as it was. A method that took the context and then issued the insert without
// it would fail this on the row count, not on the error.
func TestCreateUser_RefusesAnAlreadyCancelledContextAndInsertsNothing(t *testing.T) {
	user := &models.User{
		Enabled:  true,
		Subject:  fake.UUID(),
		Username: fake.Username(),
		Email:    fake.Email(),
	}

	err := database.CreateUser(cancelled(), nil, user)

	require.Error(t, err)
	assert.ErrorIs(t, err, context.Canceled)

	found, err := database.GetUserByEmail(context.Background(), nil, user.Email)
	require.NoError(t, err, "the read that checks the table must itself succeed")
	assert.Nil(t, found, "the refused insert wrote no row")
}

// A loader rather than a plain select, because UserLoadPermissions reaches the database through
// GetUserPermissionsByUserId and then through GetPermissionsByIds: the context has to survive two
// hops inside commondb, which is the shape the other four loaders share.
func TestUserLoadPermissions_RefusesAnAlreadyCancelledContext(t *testing.T) {
	user := createTestUser(t)

	err := database.UserLoadPermissions(cancelled(), nil, user)

	require.Error(t, err)
	assert.ErrorIs(t, err, context.Canceled)
	assert.Empty(t, user.Permissions, "nothing was loaded onto the model")
}

// Stage 6 adds the session, token and code half. The three shapes above are repeated on the
// methods this batch carries, because "the context reaches the driver" is a claim about each
// method's own body: a batch that took the ctx into its signature and left a
// context.Background() at its QuerySql would pass every other tier.

// The read every request path makes. MiddlewareSessionIdentifier, /auth/authorize,
// /auth/level1completed, /auth/completed, the token endpoint and the bearer-token middleware all
// resolve a session identifier through this one method, so it is the read most worth being able
// to abandon.
func TestGetUserSessionBySessionIdentifier_RefusesAnAlreadyCancelledContext(t *testing.T) {
	user := createTestUser(t)
	session := createTestUserSession(t, user.Id)

	got, err := database.GetUserSessionBySessionIdentifier(cancelled(), nil, session.SessionIdentifier)

	require.Error(t, err, "a read must not be issued on behalf of a caller that is already gone")
	assert.ErrorIs(t, err, context.Canceled, "and the reason must be matchable, not a sentence")
	assert.Nil(t, got, "no row is returned alongside the refusal")
}

// The write half, and the second assertion is the one that matters: a method that took the
// context and then issued the insert without it would fail on the row count rather than on the
// error. CreateCode rather than any other insert because it is the one statement #139 orders
// against a concurrent termination, so a code that appeared despite a refusal would be a code
// outside that ordering.
func TestCreateCode_RefusesAnAlreadyCancelledContextAndInsertsNothing(t *testing.T) {
	user := createTestUser(t)
	client := createTestClient(t)
	random := fake.LetterN(8)

	code := &models.Code{
		ClientId:          client.Id,
		UserId:            user.Id,
		Code:              "cancelled_" + random,
		CodeHash:          "cancelledhash_" + random,
		RedirectURI:       "https://example.com/callback",
		Scope:             "openid profile",
		IpAddress:         "192.168.1.1",
		UserAgent:         testUserAgent,
		ResponseMode:      "query",
		AuthenticatedAt:   time.Now().UTC().Truncate(time.Microsecond),
		SessionIdentifier: "cancelledsession_" + random,
		AcrLevel:          models.AcrLevel1.String(),
		AuthMethods:       "pwd",
	}

	err := database.CreateCode(cancelled(), nil, code)

	require.Error(t, err)
	assert.ErrorIs(t, err, context.Canceled)

	found, err := database.GetCodeByCodeHash(context.Background(), nil, code.CodeHash, false)
	require.NoError(t, err, "the read that checks the table must itself succeed")
	assert.Nil(t, found, "the refused insert wrote no row")
}

// A loader rather than a plain select: UserSessionLoadClients reaches the database through
// GetUserSessionClientsByUserSessionId, so the context has to survive a hop inside commondb. It
// is the shape the seven other Load* methods in this batch share.
func TestUserSessionLoadClients_RefusesAnAlreadyCancelledContext(t *testing.T) {
	user := createTestUser(t)
	client := createTestClient(t)
	session := createTestUserSessionWithClient(t, user.Id, client.Id)

	err := database.UserSessionLoadClients(cancelled(), nil, session)

	require.Error(t, err)
	assert.ErrorIs(t, err, context.Canceled)
	assert.Empty(t, session.Clients, "nothing was loaded onto the model")
}

// AcquireUserSessionRow is the acquisition #139's ordering rests on: issuance takes the session
// row before inserting its code, so a termination committing in between cannot slip past. A
// cancelled caller must be refused the row rather than told it is gone, because false and nil
// is the answer that restarts the ceremony at level 1.
func TestAcquireUserSessionRow_RefusesAnAlreadyCancelledContext(t *testing.T) {
	user := createTestUser(t)
	session := createTestUserSession(t, user.Id)

	tx, err := database.BeginTransaction(context.Background())
	require.NoError(t, err)
	defer func() { _ = database.RollbackTransaction(tx) }()

	live, err := database.AcquireUserSessionRow(cancelled(), tx, session.SessionIdentifier)

	require.Error(t, err, "a refusal, not a report that the row is gone")
	assert.ErrorIs(t, err, context.Canceled)
	assert.False(t, live)
}
