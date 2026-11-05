package datatests

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/leodip/goiabada/authserver/internal/backchannel"
	"github.com/leodip/goiabada/authserver/internal/data"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/authserver/internal/revocation"
	"github.com/leodip/goiabada/authserver/internal/usersession"
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

func (d *joinBeforeTheSessionLockDatabase) GetUserSessionsByUserId(ctx context.Context, tx *sql.Tx, userId int64) ([]record.UserSession, error) {
	sessions, err := d.Database.GetUserSessionsByUserId(ctx, tx, userId)
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
	require.NoError(t, database.SetClientBackchannelLogout(ctx, nil, race.first.Id, "https://first.example/backchannel", sessionRequired))
	race.session = createTestUserSessionWithClient(t, race.user.Id, race.first.Id)
	race.db = &joinBeforeTheSessionLockDatabase{Database: database, join: func() error {
		if err := other.SetClientBackchannelLogout(ctx, nil, race.joined.Id, "https://joined.example/backchannel", sessionRequired); err != nil {
			return err
		}
		_, err := usersession.NewManager(other).BumpUserSession(ctx, race.session.SessionIdentifier, race.joined.Id, "", "", "")
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
		told[delivery.ClientId] = delivery
	}
	require.Len(t, told, 2, "the app on the session and the app that joined it before it was taken")
	require.Contains(t, told, race.first.Id)
	require.Contains(t, told, race.joined.Id)
	require.Equal(t, "https://joined.example/backchannel", told[race.joined.Id].URI,
		"the joined app's URI as committed before the session was taken")
	require.Equal(t, sid, told[race.joined.Id].SessionIdentifier)
	require.Len(t, deliveries, 2)
}

func TestLogoutRecipients_AUserWideRevocationTellsAnAppThatJoinedBeforeTheSessionLock(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	race := newRecipientsRace(t, ctx, true)

	result, err := revocation.RevokeUserAuthStateTx(ctx, race.db, race.user.Id, "", revocation.LogoutNotice{
		Subject: race.user.Subject, UserWide: true, Live: revocation.LiveUnder(3600, 86400),
	}, func(*sql.Tx) error { return nil })

	require.NoError(t, err)
	race.requireBothTold(t, result.LogoutDeliveries, race.session.SessionIdentifier)
}

func TestLogoutRecipients_ASessionSpecificRevocationTellsAnAppThatJoinedBeforeTheSessionLock(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	race := newRecipientsRace(t, ctx, false)
	kept := createTestUserSessionWithClient(t, race.user.Id, race.first.Id)

	result, err := revocation.RevokeUserAuthStateTx(ctx, race.db, race.user.Id, kept.SessionIdentifier, revocation.LogoutNotice{
		Subject: race.user.Subject, Live: revocation.LiveUnder(3600, 86400),
	}, func(*sql.Tx) error { return nil })

	require.NoError(t, err)
	race.requireBothTold(t, result.LogoutDeliveries, race.session.SessionIdentifier)
}

func TestLogoutRecipients_AUserDeletionTellsAnAppThatJoinedBeforeTheSessionLock(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	race := newRecipientsRace(t, ctx, true)

	// The administrator's deletion: the user's row, then the deliveries, then the deletion.
	var deliveries []backchannel.Delivery
	err := database.RunInTransaction(ctx, func(tx *sql.Tx) error {
		if err := database.AcquireUserRow(ctx, tx, race.user.Id); err != nil {
			return err
		}
		var err error
		deliveries, err = revocation.UserWideDeliveries(ctx, race.db, tx, race.user.Id, race.user.Subject,
			revocation.LiveUnder(3600, 86400))
		if err != nil {
			return err
		}
		return database.DeleteUser(ctx, tx, race.user.Id)
	})

	require.NoError(t, err)
	race.requireBothTold(t, deliveries, race.session.SessionIdentifier)
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
	_, removed, err := usersession.NewManager(race.db).StartNewUserSession(ctx, signingIn.Id, usersession.Authentication{
		UserId: race.user.Id, AuthMethods: "pwd", AcrLevel: record.AcrLevel1,
		AuthTime: &now, PasswordAuthTime: &now,
	}, race.user.AuthStateGeneration, nil, usersession.Device{Identifier: "recipients-new-device", New: true}, "127.0.0.1",
		race.session, usersession.SessionLimits{IdleTimeoutInSeconds: 3600, MaxLifetimeInSeconds: 86400, MaxSessionsPerUser: 100})

	require.NoError(t, err)
	require.Len(t, removed, 1)
	race.requireBothTold(t, removed[0].LogoutDeliveries, race.session.SessionIdentifier)
}
