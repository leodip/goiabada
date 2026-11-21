package datatests

import (
	"context"
	"database/sql"
	"net/http"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/leodip/goiabada/authserver/internal/backchannel"
	"github.com/leodip/goiabada/authserver/internal/data"
	"github.com/leodip/goiabada/authserver/internal/handlers/apihandlers"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/authserver/internal/revocation"
	"github.com/leodip/goiabada/authserver/internal/usersession"
	"github.com/leodip/goiabada/core/builtin"
	"github.com/stretchr/testify/require"
)

// The apps an end of a session tells are read as last committed under the session's row, whatever
// the end read before taking it (#784 decisions 1 and 3). Each end below reads the user's sessions
// first, which on MySQL fixes the transaction's REPEATABLE READ snapshot; then, before the end takes
// the session's row, a sign-in on a second connection gives an app a back-channel logout URI and
// adds it to the session, and commits. The end must tell that app too: it deletes the session the
// app joined. An ordinary read after AcquireUserSessionRow answers the snapshot and misses it.
//
// SQLite's single connection cannot interleave the bind inside the end's transaction, so these run
// on the three engines with row locks (the sign-in's on two of them; see its test).

// joinBeforeTheSessionLockDatabase runs join once, right after the end's first read of the user's
// sessions and before it takes any session's row.
type joinBeforeTheSessionLockDatabase struct {
	data.Database
	join func() error
}

func (d *joinBeforeTheSessionLockDatabase) GetUserSessionsByUserID(ctx context.Context, tx *sql.Tx, userID int64) ([]record.UserSession, error) {
	sessions, err := d.Database.GetUserSessionsByUserID(ctx, tx, userID)
	if err == nil && d.join != nil {
		join := d.join
		d.join = nil
		err = join()
	}
	return sessions, err
}

// recipientsRace is one race: a user, an app already on session, and joined, an app with no URI yet,
// which the join gives a URI and binds to session on another connection. Both apps require sid when
// sessionRequired, so a user-wide end's token for the joined app names the session it joined.
type recipientsRace struct {
	user    *record.User
	first   *record.Client
	joined  *record.Client
	session *record.UserSession
	db      *joinBeforeTheSessionLockDatabase
}

func newRecipientsRace(t *testing.T, ctx context.Context, sessionRequired bool) *recipientsRace {
	t.Helper()
	if dbType() == data.SQLite {
		t.Skip("SQLite's one connection cannot interleave the bind inside the end's transaction")
	}
	other := secondDatabase(t)
	race := &recipientsRace{user: createTestUser(t), first: createTestClient(t), joined: createTestClient(t)}
	require.NoError(t, database.SetClientBackchannelLogout(ctx, nil, race.first.ID, "https://first.example/backchannel", sessionRequired))
	race.session = createTestUserSessionWithClient(t, race.user.ID, race.first.ID)
	race.db = &joinBeforeTheSessionLockDatabase{Database: database, join: func() error {
		if err := other.SetClientBackchannelLogout(ctx, nil, race.joined.ID, "https://joined.example/backchannel", sessionRequired); err != nil {
			return err
		}
		_, err := usersession.NewManager(other).BumpUserSession(ctx, race.session.SessionIdentifier, race.joined.ID, "", "", "")
		return err
	}}
	return race
}

// requireBothTold holds deliveries to one token each for the app already on the session and the one
// that joined it.
func (race *recipientsRace) requireBothTold(t *testing.T, deliveries []backchannel.Delivery, sid string) {
	t.Helper()
	require.Nil(t, race.db.join, "the join ran inside the end")
	told := map[int64]backchannel.Delivery{}
	for _, delivery := range deliveries {
		told[delivery.ClientID] = delivery
	}
	require.Len(t, told, 2, "the app on the session and the app that joined it before it was taken")
	require.Contains(t, told, race.first.ID)
	require.Contains(t, told, race.joined.ID)
	require.Equal(t, "https://joined.example/backchannel", told[race.joined.ID].URI,
		"the joined app's URI as committed before the session was taken")
	require.Equal(t, sid, told[race.joined.ID].SessionIdentifier)
	require.Len(t, deliveries, 2)
}

func TestLogoutRecipients_AUserWideRevocationTellsAnAppThatJoinedBeforeTheSessionLock(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	race := newRecipientsRace(t, ctx, true)

	result, err := revocation.RevokeUserAuthStateTx(ctx, race.db, race.user.ID, "", revocation.LogoutNotice{
		Subject: race.user.Subject, UserWide: true, Live: revocation.LiveUnder(3600, 86400),
	}, func(*sql.Tx) error { return nil })

	require.NoError(t, err)
	race.requireBothTold(t, result.LogoutDeliveries, race.session.SessionIdentifier)
}

func TestLogoutRecipients_ASessionSpecificRevocationTellsAnAppThatJoinedBeforeTheSessionLock(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	race := newRecipientsRace(t, ctx, false)
	kept := createTestUserSessionWithClient(t, race.user.ID, race.first.ID)

	result, err := revocation.RevokeUserAuthStateTx(ctx, race.db, race.user.ID, kept.SessionIdentifier, revocation.LogoutNotice{
		Subject: race.user.Subject, Live: revocation.LiveUnder(3600, 86400),
	}, func(*sql.Tx) error { return nil })

	require.NoError(t, err)
	race.requireBothTold(t, result.LogoutDeliveries, race.session.SessionIdentifier)
}

// The administrator's deletion, through its handler: the administrators' lock, the user's row, the
// deliveries, then the deletion.
func TestLogoutRecipients_AUserDeletionTellsAnAppThatJoinedBeforeTheSessionLock(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if dbType() == data.Postgres {
		// The deletion holds the user's row FOR UPDATE. The bind writes the session's row back after
		// taking it, and PostgreSQL checks that row's user_id foreign key because its own transaction
		// wrote the row, taking FOR KEY SHARE on the user's row: the bind waits for the deletion, so it
		// cannot commit inside it here. Outside a test the two meet in a deadlock, and PostgreSQL may
		// abort either. A bind chosen as the victim reruns and finds the session gone, so no app joins
		// one the deletion ends; a deletion chosen reruns after the bind committed and tells the app
		// that joined. TestLogoutRecipients_ADisableAndASessionBindResolveTheirPostgreSQLDeadlock
		// forces that cycle with the disable, which takes the user's row the same way.
		t.Skip("PostgreSQL's bind waits for the deletion's lock on the user's row")
	}
	race := newRecipientsRace(t, ctx, true)
	managePermissionRow(t)

	sender := &recordedLogoutTokens{}
	id := strconv.FormatInt(race.user.ID, 10)
	rr := serveUserWrite(ctx, apihandlers.HandleUserDelete(race.db, &countingAuditLogger{}, noNotices{}, sender),
		http.MethodDelete, "/api/v1/admin/users/"+id, map[string]string{"id": id}, nil,
		"logout-recipients-test", builtin.AuthServerResourceIdentifier+":"+builtin.ManagePermissionIdentifier)

	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	race.requireBothTold(t, sender.deliveries, race.session.SessionIdentifier)
}

// attemptCountingDatabase counts its transactions' attempts, a deadlock's rerun included, and can
// run a hook as the transaction takes a session's row and as it writes the session back.
type attemptCountingDatabase struct {
	data.Database
	attempts          atomic.Int32
	beforeSessionLock func()
	beforeSessionSave func(context.Context) error
}

func (d *attemptCountingDatabase) RunInTransaction(ctx context.Context, fn func(tx *sql.Tx) error) error {
	return d.Database.RunInTransaction(ctx, func(tx *sql.Tx) error {
		d.attempts.Add(1)
		return fn(tx)
	})
}

func (d *attemptCountingDatabase) AcquireUserSessionRow(ctx context.Context, tx *sql.Tx, sessionIdentifier string) (bool, error) {
	if d.beforeSessionLock != nil {
		d.beforeSessionLock()
	}
	return d.Database.AcquireUserSessionRow(ctx, tx, sessionIdentifier)
}

func (d *attemptCountingDatabase) UpdateUserSession(ctx context.Context, tx *sql.Tx, session *record.UserSession) error {
	if d.beforeSessionSave != nil {
		if err := d.beforeSessionSave(ctx); err != nil {
			return err
		}
	}
	return d.Database.UpdateUserSession(ctx, tx, session)
}

// On PostgreSQL the administrator's disable, which holds the user's row FOR UPDATE before it takes
// each session's row (#796 decision 1), and a sign-in binding an app to one of those sessions, which
// holds the session's row and then needs FOR KEY SHARE on the user's for the foreign-key check of
// the row it writes back, wait for each other. The engine aborts one with a deadlock and the
// transaction retry reruns it. Either way the disable ends the session, and an app whose bind
// committed is among those it tells; a bind that lost finds the session gone.
func TestLogoutRecipients_ADisableAndASessionBindResolveTheirPostgreSQLDeadlock(t *testing.T) {
	if dbType() != data.Postgres {
		t.Skip("only PostgreSQL checks the session's user foreign key when the bind writes the row back")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	managePermissionRow(t)
	race := newRecipientsRace(t, ctx, true)
	if !race.user.Enabled {
		enabled, err := database.TrySetUserEnabled(ctx, nil, race.user.ID, false, true)
		require.NoError(t, err)
		require.True(t, enabled)
	}
	require.NoError(t, database.SetClientBackchannelLogout(ctx, nil, race.joined.ID, "https://joined.example/backchannel", true))

	// The bind holds the session's row and waits, before writing it back, until the disable holds
	// the user's row and comes to take the session's.
	bindHoldsTheSession := make(chan struct{})
	disableHoldsTheUser := make(chan struct{})
	disableDB := &attemptCountingDatabase{Database: database,
		beforeSessionLock: sync.OnceFunc(func() { close(disableHoldsTheUser) })}
	bindDB := &attemptCountingDatabase{Database: secondDatabase(t),
		beforeSessionSave: func(ctx context.Context) error {
			select {
			case <-bindHoldsTheSession:
			default:
				close(bindHoldsTheSession)
			}
			select {
			case <-disableHoldsTheUser:
				return nil
			case <-ctx.Done():
				return ctx.Err()
			}
		}}
	bindDone := make(chan error, 1)
	go func() {
		_, err := usersession.NewManager(bindDB).BumpUserSession(ctx, race.session.SessionIdentifier, race.joined.ID, "", "", "")
		bindDone <- err
	}()
	select {
	case <-bindHoldsTheSession:
	case err := <-bindDone:
		t.Fatalf("the bind returned before it came to write the session back: %v", err)
	case <-ctx.Done():
		t.Fatal("the bind never came to write the session back")
	}

	sender := &recordedLogoutTokens{}
	id := strconv.FormatInt(race.user.ID, 10)
	rr := serveUserWrite(ctx, apihandlers.HandleUserEnabledPut(disableDB, &countingAuditLogger{}, sender),
		http.MethodPut, "/api/v1/admin/users/"+id+"/enabled", map[string]string{"id": id},
		[]byte(`{"enabled":false}`), "disable-bind-deadlock-test",
		builtin.AuthServerResourceIdentifier+":"+builtin.ManagePermissionIdentifier)
	var bindErr error
	select {
	case bindErr = <-bindDone:
	case <-ctx.Done():
		t.Fatal("the bind never finished")
	}

	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	require.Equal(t, int32(3), disableDB.attempts.Load()+bindDB.attempts.Load(),
		"the deadlock's victim ran a second attempt, and each transaction otherwise one (disable %d, bind %d)",
		disableDB.attempts.Load(), bindDB.attempts.Load())
	disabled, err := database.GetUserByID(ctx, nil, race.user.ID)
	require.NoError(t, err)
	require.NotNil(t, disabled)
	require.False(t, disabled.Enabled, "the user is disabled")
	left, err := database.GetUserSessionByID(ctx, nil, race.session.ID)
	require.NoError(t, err)
	require.Nil(t, left, "the disable ended the session")

	told := sender.toldClientIDs()
	require.True(t, told[race.first.ID], "the app already on the session is told")
	if bindDB.attempts.Load() == 1 {
		require.NoError(t, bindErr, "the disable was the victim, and the bind committed")
		require.True(t, told[race.joined.ID], "the app whose bind committed before the disable's rerun is told")
	} else {
		require.ErrorContains(t, bindErr, "user session is nil", "the bind was the victim, and its rerun finds the session gone")
		require.False(t, told[race.joined.ID], "the bind never committed, so its app is not on the session")
	}
}

func TestLogoutRecipients_ASignInRemovalTellsAnAppThatJoinedBeforeTheSessionLock(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if dbType() == data.MSSQL {
		// The sign-in has inserted its own session's app before it reads the user's sessions, and at
		// SQL Server's locking READ COMMITTED the bind's read of the session's apps waits for that
		// uncommitted row, so the bind cannot commit inside the sign-in here. Outside a test the two
		// meet in a deadlock the transaction retry resolves.
		t.Skip("SQL Server's bind waits for the sign-in's uncommitted association")
	}
	race := newRecipientsRace(t, ctx, false)
	signingIn := createTestClient(t)

	now := time.Now().UTC()
	_, removed, err := usersession.NewManager(race.db).StartNewUserSession(ctx, signingIn.ID, usersession.Authentication{
		UserID: race.user.ID, AuthMethods: "pwd", ACRLevel: record.ACRLevel1,
		AuthTime: &now, PasswordAuthTime: &now,
	}, race.user.AuthStateGeneration, nil, usersession.Device{Identifier: "recipients-new-device", New: true}, "127.0.0.1",
		race.session, usersession.SessionLimits{IdleTimeoutInSeconds: 3600, MaxLifetimeInSeconds: 86400, MaxSessionsPerUser: 100})

	require.NoError(t, err)
	require.Len(t, removed, 1)
	race.requireBothTold(t, removed[0].LogoutDeliveries, race.session.SessionIdentifier)
}

// joinBeforeTheTransactionDatabase runs join once, as the end opens its transaction: after every read
// the end makes before it, and before it takes the session's row.
type joinBeforeTheTransactionDatabase struct {
	data.Database
	join func() error
}

func (d *joinBeforeTheTransactionDatabase) RunInTransaction(ctx context.Context, fn func(tx *sql.Tx) error) error {
	if d.join != nil {
		join := d.join
		d.join = nil
		if err := join(); err != nil {
			return err
		}
	}
	return d.Database.RunInTransaction(ctx, fn)
}

// A hinted sign-out ends its app's part of the session, and the session with it when that app is the
// session's last. Whether it is the last is read under the session's row: an app a sign-in binds to
// the session after the sign-out read it, and before the sign-out takes its row, keeps the session,
// whose deletion would take that app's row untold. The bind commits before the end's transaction
// opens, which is the window the end's read leaves, so this runs on every engine.
func TestLogoutRecipients_AHintedSignOutByTheLastAppKeepsASessionAnAppJoinedBeforeTheSessionLock(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	user, hinted, joined := createTestUser(t), createTestClient(t), createTestClient(t)
	session := createTestUserSessionWithClient(t, user.ID, hinted.ID)
	db := &joinBeforeTheTransactionDatabase{Database: database, join: func() error {
		_, err := usersession.NewManager(database).BumpUserSession(ctx, session.SessionIdentifier, joined.ID, "", "", "")
		return err
	}}

	end, err := revocation.EndClientPartTx(ctx, db, session.SessionIdentifier, hinted.ClientIdentifier)

	require.NoError(t, err)
	require.Nil(t, db.join, "the join ran as the end opened its transaction")
	require.NotNil(t, end.Ended, "the hinted app's part ended")
	require.Equal(t, hinted.ID, end.Ended.ClientID)
	require.False(t, end.SessionDeleted, "the app that joined keeps the session")

	kept, err := database.GetUserSessionBySessionIdentifier(ctx, nil, session.SessionIdentifier)
	require.NoError(t, err)
	require.NotNil(t, kept, "the session stays")
	apps, err := database.GetUserSessionClientsByUserSessionID(ctx, nil, session.ID)
	require.NoError(t, err)
	require.Len(t, apps, 1)
	require.Equal(t, joined.ID, apps[0].ClientID, "with the app that joined, and without the hinted one")
}
