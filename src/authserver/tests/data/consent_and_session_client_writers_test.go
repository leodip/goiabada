package datatests

import (
	"context"
	"database/sql"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/leodip/goiabada/authserver/internal/data"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/authserver/internal/userconsent"
	"github.com/leodip/goiabada/authserver/internal/usersession"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The consent screen's save and a session's bump each read "is there a row for this pair" and then
// insert or update, and migration 000055 gave both pairs a unique key (#249, #437). Two callers that
// overlap can therefore both read "absent" and both insert; the engine refuses the second, which on
// PostgreSQL aborts its transaction, and the writer reruns it once, reading what the winner
// committed. A mock shows the rerun is requested; only an engine shows the refusal happens and that
// the rerun succeeds against it, which is what this file proves.
//
// The overlap is forced rather than hoped for. Each caller reads through a decorator that, after the
// read has returned, waits until the other caller has also read, so both decide from "absent" and
// both go on to insert. Only the first two reads wait: a rerun's read passes straight through. The
// decorators also count reads, so the loser is the caller that read twice, and the assertion that
// there is exactly one says the rerun came from the lost key and not from a deadlock's.

// rendezvous holds the first n arrivals until all n are there. Every later arrival, a rerun's,
// passes at once. The wait is bounded, so a caller that never arrives fails the test instead of
// hanging it.
type rendezvous struct {
	t       *testing.T
	what    string
	n       int32
	arrived atomic.Int32
	release chan struct{}
}

func newRendezvous(t *testing.T, what string, n int32) *rendezvous {
	return &rendezvous{t: t, what: what, n: n, release: make(chan struct{})}
}

func (r *rendezvous) meet() {
	arrival := r.arrived.Add(1)
	switch {
	case arrival > r.n:
		return
	case arrival == r.n:
		close(r.release)
	default:
		select {
		case <-r.release:
		case <-time.After(blockedCeiling):
			r.t.Errorf("%s: the other caller never reached the rendezvous within %s", r.what, blockedCeiling)
		}
	}
}

// consentReader is what userconsent.Record is handed for one caller: the real database, with the
// consent's read followed by the rendezvous.
type consentReader struct {
	data.Database
	rendezvous *rendezvous
	reads      atomic.Int32
}

func (c *consentReader) GetConsentByUserIdAndClientId(ctx context.Context, tx *sql.Tx, userId int64, clientId int64) (*record.UserConsent, error) {
	consent, err := c.Database.GetConsentByUserIdAndClientId(ctx, tx, userId, clientId)
	c.reads.Add(1)
	c.rendezvous.meet()
	return consent, err
}

// sessionReader is the same for a session's bump: the read of the session's associations is the
// last read before the decision between inserting and updating.
type sessionReader struct {
	data.Database
	rendezvous *rendezvous
	reads      atomic.Int32
}

func (s *sessionReader) UserSessionLoadClients(ctx context.Context, tx *sql.Tx, userSession *record.UserSession) error {
	err := s.Database.UserSessionLoadClients(ctx, tx, userSession)
	s.reads.Add(1)
	s.rendezvous.meet()
	return err
}

// consentsOf is the rows a user holds for one client, read through the data layer.
func consentsOf(t *testing.T, userId, clientId int64) []record.UserConsent {
	t.Helper()

	all, err := database.GetConsentsByUserId(context.Background(), nil, userId)
	require.NoError(t, err)
	var pair []record.UserConsent
	for _, consent := range all {
		if consent.ClientId == clientId {
			pair = append(pair, consent)
		}
	}
	return pair
}

// associationsOf is the session's associations for one client.
func associationsOf(t *testing.T, sessionIdentifier string, clientId int64) (pair []record.UserSessionClient, all []record.UserSessionClient) {
	t.Helper()

	session, err := database.GetUserSessionBySessionIdentifier(context.Background(), nil, sessionIdentifier)
	require.NoError(t, err)
	require.NotNil(t, session)
	require.NoError(t, database.UserSessionLoadClients(context.Background(), nil, session))
	for _, association := range session.Clients {
		if association.ClientId == clientId {
			pair = append(pair, association)
		}
	}
	return pair, session.Clients
}

// A save for a pair that has a row rewrites it in place, on every engine, and records the save's
// time: the account's consents page shows it (#115). The second save's scope replaces the first's.
func TestUserConsentRecord_ASecondSaveRewritesTheRowAndRefreshesItsDate(t *testing.T) {
	ctx := context.Background()
	user := createTestUser(t)
	client := createTestClient(t)

	first, err := userconsent.Record(ctx, database, user.Id, client.Id, "openid profile email")
	require.NoError(t, err)
	time.Sleep(10 * time.Millisecond) // a later instant than the first save, at every engine's resolution
	second, err := userconsent.Record(ctx, database, user.Id, client.Id, "openid")
	require.NoError(t, err)

	assert.Equal(t, first.Id, second.Id, "the second save rewrote the row, it did not add one")
	rows := consentsOf(t, user.Id, client.Id)
	require.Len(t, rows, 1, "one row for the pair")
	assert.Equal(t, "openid", rows[0].Scope, "the scope is what the second save ticked, not appended to the first's")
	require.True(t, rows[0].GrantedAt.Valid)
	assert.Truef(t, rows[0].GrantedAt.Time.After(first.GrantedAt.Time),
		"granted_at is the second save's time, %v, after the first's, %v", rows[0].GrantedAt.Time, first.GrantedAt.Time)
}

// Two saves that both read "no consent" and both insert: one wins the key and the other reruns,
// reads the winner's row and rewrites it. Both callers succeed, the pair has one row, and it holds
// the scope of the save that ran last, which is the loser's.
func TestUserConsentRecord_TwoSavesThatOverlapBothSucceedAndLeaveOneRow(t *testing.T) {
	skipWhereTransactionsCannotOverlap(t)

	scopes := [2]string{"openid profile", "openid email"}
	for round := 0; round < concurrentRounds; round++ {
		ctx, cancel := context.WithTimeout(context.Background(), lockWaitCeiling)
		user := createTestUser(t)
		client := createTestClient(t)
		meet := newRendezvous(t, "the two consent reads", 2)
		callers := [2]*consentReader{{Database: database, rendezvous: meet}, {Database: database, rendezvous: meet}}

		type outcome struct {
			consent *record.UserConsent
			err     error
		}
		var outcomes [2]outcome
		var wg sync.WaitGroup
		for i := range callers {
			wg.Add(1)
			go func() {
				defer wg.Done()
				outcomes[i].consent, outcomes[i].err = userconsent.Record(ctx, callers[i], user.Id, client.Id, scopes[i])
			}()
		}
		wg.Wait()
		cancel()

		for i, o := range outcomes {
			require.NoErrorf(t, o.err, "round %d: caller %d succeeds, a loser on the key is rerun", round, i)
			require.NotNilf(t, o.consent, "round %d: caller %d is handed the row it saved", round, i)
		}
		rows := consentsOf(t, user.Id, client.Id)
		require.Lenf(t, rows, 1, "round %d: the pair has one row however the two saves overlapped", round)

		reads := [2]int32{callers[0].reads.Load(), callers[1].reads.Load()}
		loser := -1
		switch reads {
		case [2]int32{2, 1}:
			loser = 0
		case [2]int32{1, 2}:
			loser = 1
		default:
			require.Failf(t, "the reruns were not the lost key's", "round %d: reads per caller were %v, and one caller reading twice is the lost key", round, reads)
		}
		assert.Equalf(t, scopes[loser], rows[0].Scope, "round %d: the loser reran after the winner committed, so the last writer's scope is the one that stays", round)
		assert.Equalf(t, rows[0].Id, outcomes[0].consent.Id, "round %d: both callers saved the one row", round)
		assert.Equalf(t, rows[0].Id, outcomes[1].consent.Id, "round %d: both callers saved the one row", round)
	}
}

// A second bump for a client the session already holds updates the association it has, on every
// engine: the pair stays one row and its last-accessed time moves on.
func TestBumpUserSession_ASecondBumpForTheSameClientUpdatesItsAssociation(t *testing.T) {
	ctx := context.Background()
	user := createTestUser(t)
	held := createTestClient(t)
	added := createTestClient(t)
	session := createTestUserSessionWithClient(t, user.Id, held.Id)
	manager := usersession.NewManager(nil, "", database)

	_, err := manager.BumpUserSession(ctx, session.SessionIdentifier, added.Id, "pwd", record.AcrLevel1, "")
	require.NoError(t, err)
	pair, all := associationsOf(t, session.SessionIdentifier, added.Id)
	require.Len(t, pair, 1, "the first bump added the client")
	require.Len(t, all, 2)
	firstAccessed := pair[0].LastAccessed

	time.Sleep(10 * time.Millisecond)
	_, err = manager.BumpUserSession(ctx, session.SessionIdentifier, added.Id, "pwd", record.AcrLevel1, "")
	require.NoError(t, err)

	pair, all = associationsOf(t, session.SessionIdentifier, added.Id)
	require.Len(t, pair, 1, "the second bump found the association and updated it")
	require.Len(t, all, 2, "and added nothing")
	assert.Truef(t, pair[0].LastAccessed.After(firstAccessed), "last_accessed moved on: %v after %v", pair[0].LastAccessed, firstAccessed)
}

// Two bumps of one session for a client it does not hold yet. Each takes the session's row before it
// reads anything (#542), so they queue: the second reads the association the first committed and
// updates it, neither loses the key and neither reruns. Both succeed and the session holds the client
// once. Until the row was taken first, both read the client as absent, one lost the key and reran
// (#249); the rerun stays for an association written by something that does not take the row.
//
// The two are started behind a transaction holding the row, so both are waiting at once when it is
// released, rather than one finishing before the other starts.
func TestBumpUserSession_TwoBumpsThatOverlapQueueOnTheSessionAndLeaveOnePair(t *testing.T) {
	skipWhereTransactionsCannotOverlap(t)

	ctx := context.Background()
	user := createTestUser(t)
	held := createTestClient(t)
	added := createTestClient(t)
	session := createTestUserSessionWithClient(t, user.Id, held.Id)

	holder, err := database.BeginTransaction(ctx)
	require.NoError(t, err)
	defer func() { _ = database.RollbackTransaction(ctx, holder) }()
	live, err := database.AcquireUserSessionRow(ctx, holder, session.SessionIdentifier)
	require.NoError(t, err)
	require.True(t, live)

	// A rendezvous of one never waits: each read is only counted.
	callers := [2]*sessionReader{
		{Database: secondDatabase(t), rendezvous: newRendezvous(t, "no rendezvous", 1)},
		{Database: secondDatabase(t), rendezvous: newRendezvous(t, "no rendezvous", 1)},
	}
	var bumps [2]*blockedParty[error]
	for i := range callers {
		bumps[i] = goBlocked(t, fmt.Sprintf("bump %d", i), holder, func(reached func()) error {
			reached()
			_, bumpErr := usersession.NewManager(nil, "", callers[i]).
				BumpUserSession(ctx, session.SessionIdentifier, added.Id, "pwd", record.AcrLevel1, "")
			return bumpErr
		})
	}
	for _, bump := range bumps {
		bump.requireBlocked(t)
	}
	require.NoError(t, database.RollbackTransaction(ctx, holder))
	for i, bump := range bumps {
		require.NoErrorf(t, bump.await(t), "bump %d succeeds", i)
	}

	pair, all := associationsOf(t, session.SessionIdentifier, added.Id)
	require.Len(t, pair, 1, "the session holds the client once")
	assert.Len(t, all, 2, "the client it already held, and the one the bumps added")
	assert.Equal(t, [2]int32{1, 1}, [2]int32{callers[0].reads.Load(), callers[1].reads.Load()},
		"each bump read the associations once: queued on the session's row, neither lost the key")
}
