package datatests

import (
	"database/sql"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/brianvoe/gofakeit/v6"
	"github.com/gorilla/sessions"
	"github.com/leodip/goiabada/authserver/internal/handlers"
	"github.com/leodip/goiabada/core/data"
	"github.com/leodip/goiabada/core/enums"
	"github.com/leodip/goiabada/core/models"
	"github.com/leodip/goiabada/core/oauth"
	"github.com/leodip/goiabada/core/user"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// #139 STAGE 7: DELETECLIENT JOINS THE LOCK ORDER.
//
// Decision 10 ended "DeleteClient is exempt, and measured so rather than argued", and the
// measurement was honest: it did not conflict with the session-side transactions AS THEY STOOD.
// Stage 4 changed how they stand. Every one of them now takes the user_sessions row first, which
// means it holds that session's user_session_clients rows, by cascade, from its first statement.
// DeleteClient's own cascade wants exactly those rows, and by the time it asks for one it already
// holds that client's codes and the refresh tokens it deleted explicitly, which the other side is
// about to sweep. Each holds half of what the other wants: a deadlock on PostgreSQL, MySQL and SQL
// Server, with the session-side transaction the victim on the last two.
//
// So the rule gains a row and reads: users, then clients, then user_sessions, then the grants.
// DeleteClient takes the clients row exclusively, reads the sessions associated with it and takes
// their rows, and only then deletes. The three transactions that write an association row or a
// code take the same clients row SHARED first, which is what makes that read complete: two shared
// holders do not conflict, so concurrent sign-ins are unaffected, and a deletion waits behind
// in-flight ceremonies rather than every ceremony waiting behind every other.
//
// WHAT THIS FILE IS FOR, and what it is not. The statement ORDER each site issues is pinned where
// it is visible, in unit tests over mocks and a scripted driver: commondb's
// client_delete_order_test.go, core/user's usersession_manager_lock_order_test.go and the
// authserver handler's own sequence test. This tier answers the question a mock cannot, which is
// what two or three real transactions of those shapes do to each other on a real catalog, on all
// four engines. Every case here therefore asserts the absence of a cycle AND the outcome each
// party is owed, because "neither was aborted" is satisfied by two transactions that never met.

// clientDeleteFixture is one session reaching TWO clients, the one about to be deleted and a
// survivor, with a grant of each hanging off it and a ROPC token of the deleted client beside
// them.
//
// The survivor is what makes the outcome assertions mean something: a case that only had the
// deleted client's rows could not tell "the other party did its work" from "the cascade removed
// everything anyway". The ROPC token is production-shaped and load-bearing rather than thorough:
// refresh_tokens.client_id is NO ACTION on all four engines and only code_id is CASCADE, so
// DeleteClient's explicit token delete is the statement that really does take a client's tokens
// before its cascade runs, and that is the half of the original cycle the session side waits on.
type clientDeleteFixture struct {
	// db is the handle every row of this fixture was seeded on, and the one its assertions read
	// back through. It is a field rather than the package global because the RCSI pairs build
	// the same fixture on a different database, where a reload on the package handle would find
	// a different row of the same shape under the same identity value and pass for the wrong
	// reason (see TestRCSI_TheFixtureIsTheDatabaseUnderTest).
	db data.Database

	user     *models.User
	session  *models.UserSession
	doomed   *models.Client
	survivor *models.Client

	doomedCode   *models.Code
	survivorCode *models.Code

	// doomedToken and survivorToken descend from the two codes and carry the session identifier,
	// so the session-scoped sweeps reach them.
	doomedToken   *models.RefreshToken
	survivorToken *models.RefreshToken

	// ropcToken names the doomed client directly and descends from no code, which is the row the
	// explicit delete is for.
	ropcToken *models.RefreshToken
}

func newClientDeleteFixture(t *testing.T) *clientDeleteFixture {
	return newClientDeleteFixtureOn(t, database)
}

func newClientDeleteFixtureOn(t *testing.T, db data.Database) *clientDeleteFixture {
	t.Helper()

	f := &clientDeleteFixture{
		db:       db,
		user:     createTestUserOn(t, db),
		doomed:   createTestClientOn(t, db),
		survivor: createTestClientOn(t, db),
	}
	f.session = createTestUserSessionWithClientOn(t, db, f.user.Id, f.doomed.Id)
	require.NoError(t, db.CreateUserSessionClient(nil, &models.UserSessionClient{
		UserSessionId: f.session.Id,
		ClientId:      f.survivor.Id,
		Started:       time.Now().UTC().Truncate(time.Microsecond),
		LastAccessed:  time.Now().UTC().Truncate(time.Microsecond),
	}), "associating the survivor with the session")

	f.doomedCode = createTestCodeInSessionOn(t, db, f.doomed.Id, f.user.Id, f.session.SessionIdentifier)
	f.survivorCode = createTestCodeInSessionOn(t, db, f.survivor.Id, f.user.Id, f.session.SessionIdentifier)
	f.doomedToken = createTokenOfCodeOn(t, db, f.doomed.Id, f.user.Id, f.doomedCode.Id, f.session.SessionIdentifier)
	f.survivorToken = createTokenOfCodeOn(t, db, f.survivor.Id, f.user.Id, f.survivorCode.Id, f.session.SessionIdentifier)

	f.ropcToken = &models.RefreshToken{
		UserId:            sql.NullInt64{Int64: f.user.Id, Valid: true},
		ClientId:          sql.NullInt64{Int64: f.doomed.Id, Valid: true},
		RefreshTokenJti:   gofakeit.UUID(),
		SessionIdentifier: f.session.SessionIdentifier,
		RefreshTokenType:  "Refresh",
		Scope:             "openid profile",
		IssuedAt:          sql.NullTime{Time: time.Now().UTC().Truncate(time.Microsecond), Valid: true},
		ExpiresAt:         sql.NullTime{Time: time.Now().UTC().Add(time.Hour).Truncate(time.Microsecond), Valid: true},
		MaxLifetime:       sql.NullTime{Time: time.Now().UTC().Add(24 * time.Hour).Truncate(time.Microsecond), Valid: true},
	}
	require.NoError(t, db.CreateRefreshToken(nil, f.ropcToken), "the ROPC token of the doomed client")

	return f
}

// assertDoomedClientGone is what "the deletion committed" means in rows: the client, its codes,
// its tokens and its association are all gone.
func (f *clientDeleteFixture) assertDoomedClientGone(t *testing.T) {
	t.Helper()

	client, err := f.db.GetClientById(nil, f.doomed.Id)
	require.NoError(t, err, "reloading the deleted client")
	assert.Nil(t, client, "the deleted client must be gone")

	code, err := f.db.GetCodeById(nil, f.doomedCode.Id)
	require.NoError(t, err, "reloading the deleted client's code")
	assert.Nil(t, code, "the deleted client's code goes with it by cascade")

	for _, tc := range []struct {
		id   int64
		what string
	}{
		{f.doomedToken.Id, "the deleted client's offline token"},
		{f.ropcToken.Id, "the deleted client's ROPC token"},
	} {
		token, err := f.db.GetRefreshTokenById(nil, tc.id)
		require.NoErrorf(t, err, "reloading %s", tc.what)
		assert.Nilf(t, token, "%s must be gone once its client is", tc.what)
	}

	assert.Empty(t, associationsOfOn(t, f.db, f.doomed.Id),
		"the deleted client's association row goes with it by cascade")
}

// associationsOf reads one client's association rows through the method DeleteClient itself uses.
func associationsOf(t *testing.T, clientId int64) []models.UserSessionClient {
	return associationsOfOn(t, database, clientId)
}

func associationsOfOn(t *testing.T, db data.Database, clientId int64) []models.UserSessionClient {
	t.Helper()
	rows, err := db.GetUserSessionClientsByClientId(nil, clientId)
	require.NoError(t, err, "reading the client's association rows")
	return rows
}

// insertAssociation is the write StartNewUserSession and BumpUserSession make when a session
// first reaches a client, in the order they make it: the shared client acquisition, then the row.
// takeTheLock is what a mutation turns off, which is the negative control for gate 1.
func insertAssociation(db data.Database, tx *sql.Tx, sessionId, clientId int64, takeTheLock bool) error {
	if takeTheLock {
		if err := db.AcquireClientRowShared(tx, clientId); err != nil {
			return err
		}
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	return db.CreateUserSessionClient(tx, &models.UserSessionClient{
		UserSessionId: sessionId,
		ClientId:      clientId,
		Started:       now,
		LastAccessed:  now,
	})
}

// =============================================================================
// GATE 1: the discovery barrier holds on every engine.
//
// DeleteClient's association read is complete only if nothing can insert one while it holds the
// clients row. On MySQL and SQL Server a foreign key reference would give that for free, because a
// child insert takes a shared lock on the parent and conflicts with the exclusive acquisition. On
// PostgreSQL it would not: an UPDATE touching no key column takes FOR NO KEY UPDATE and a foreign
// key check takes FOR KEY SHARE, and those two do not conflict. So the barrier has to be an
// acquisition the INSERTER also takes, and that is what this measures.
// =============================================================================

func TestClientDelete_TheDiscoveryBarrierHolds(t *testing.T) {
	runClientDeleteDiscoveryBarrier(t, database, secondDatabase(t))
}

// TestClientDelete_TheDiscoveryBarrierHolds_RCSI is the same gate against a SQL Server database
// with READ_COMMITTED_SNAPSHOT on (#139 stage 8). RCSI is the setting that stops READ COMMITTED
// statements from taking shared read locks, so what this measures is that neither of the two
// things that queue the insert on SQL Server is served from the row version store instead: the
// inserter's own HOLDLOCK acquisition, and the shared lock its foreign key check takes on the
// parent. The mutation control for the acquisition specifically lives on PostgreSQL, which is
// the engine where the FK check does not conflict and the acquisition is therefore the whole
// barrier: see the gate header above.
func TestClientDelete_TheDiscoveryBarrierHolds_RCSI(t *testing.T) {
	f := rcsiDatabase(t)
	runClientDeleteDiscoveryBarrier(t, f.primary, f.secondary)
}

func runClientDeleteDiscoveryBarrier(t *testing.T, db data.Database, other data.Database) {
	f := newClientDeleteFixtureOn(t, db)
	joiner := createTestUserSessionOn(t, db, f.user.Id)

	// Read BEFORE the transaction opens, and it has to be. sqlitedb calls SetMaxOpenConns(1), so
	// a nil-transaction read issued while tx is held asks the pool for the one connection tx owns
	// and waits for it forever: database/sql puts no deadline on that acquisition, so it is a hang
	// rather than an error. It is the same constraint CreateAuthCode's doc comment states about
	// its own client lookup.
	before := len(associationsOfOn(t, db, f.doomed.Id))

	tx, err := db.BeginTransaction()
	require.NoError(t, err, "opening the deletion's transaction")
	defer func() { _ = db.RollbackTransaction(tx) }()

	require.NoError(t, db.AcquireClientRow(tx, f.doomed.Id),
		"the deletion takes the clients row exclusively, which is its first statement")

	insert := goBlocked(t, "a session joining the client", tx, func(reached func()) error {
		otherTx, err := other.BeginTransaction()
		if err != nil {
			reached()
			return err
		}
		defer func() { _ = other.RollbackTransaction(otherTx) }()
		reached()
		if err := insertAssociation(other, otherTx, joiner.Id, f.doomed.Id, true); err != nil {
			return err
		}
		return other.CommitTransaction(otherTx)
	})

	// The whole gate: the insert must be WAITING, on every engine, while the deletion holds the
	// clients row. With the inserter's shared acquisition removed, PostgreSQL lets it through and
	// this line is what fails.
	insert.requireBlocked(t)
	insert.requireStillWaiting(t)

	// And what the barrier is for: the set the deletion read while holding the row could not grow
	// underneath it, and the held-back insert lands only once the row is released.
	require.NoError(t, db.CommitTransaction(tx), "releasing the deletion's transaction")
	require.NoError(t, insert.await(t), "the insert proceeds once the row is released")

	assert.Equal(t, before+1, len(associationsOfOn(t, db, f.doomed.Id)),
		"the association the barrier held back lands afterwards, which is what makes it a wait rather than a refusal")
}

// =============================================================================
// GATE 2 AND THE ISSUANCE PAIR: a ceremony against a deletion of the client it is minting for.
// =============================================================================

func TestLockOrder_ClientDeleteAgainstIssuance(t *testing.T) {
	runClientDeleteAgainstIssuance(t, database, secondDatabase(t))
}

// TestLockOrder_ClientDeleteAgainstIssuance_RCSI is the pair stage 7 exists for, run against a
// SQL Server database with READ_COMMITTED_SNAPSHOT on (#139 stage 8).
//
// It is here because the argument for not running it was not sound. "RCSI can only remove lock
// conflicts, so a cycle that does not form with it off cannot appear with it on" does not
// follow: removing a conflict changes which interleavings are REACHABLE, and a transaction that
// no longer stops at a read can go on to ask for a lock it never previously reached. DeleteClient
// contains exactly that shape, a plain read of the association rows between its exclusive client
// acquisition and the session rows it takes next, so the deletion's own progress is one of the
// things RCSI changes. That has to be measured rather than reasoned about.
func TestLockOrder_ClientDeleteAgainstIssuance_RCSI(t *testing.T) {
	f := rcsiDatabase(t)
	runClientDeleteAgainstIssuance(t, f.primary, f.secondary)
}

func runClientDeleteAgainstIssuance(t *testing.T, db data.Database, other data.Database) {
	t.Run("the ceremony goes first and the deletion waits", func(t *testing.T) {
		f := newClientDeleteFixtureOn(t, db)

		tx, err := db.BeginTransaction()
		require.NoError(t, err, "opening the ceremony's transaction")
		defer func() { _ = db.RollbackTransaction(tx) }()

		// The ceremony's own order, production's, stopped between its acquisitions and its insert.
		require.NoError(t, db.AcquireUserRow(tx, f.user.Id), "the ceremony takes the users row")
		require.NoError(t, db.AcquireClientRowShared(tx, f.doomed.Id),
			"the ceremony takes the clients row, shared")
		live, err := db.AcquireUserSessionRow(tx, f.session.SessionIdentifier)
		require.NoError(t, err, "the ceremony takes the session row")
		require.True(t, live)

		deletion := goBlocked(t, "the client deletion", tx, func(reached func()) error {
			reached()
			return other.DeleteClient(nil, f.doomed.Id)
		})

		// The deletion stops at its EXCLUSIVE client acquisition, which is its first statement,
		// holding nothing. That is the corrected schedule: an earlier draft had it blocking at the
		// session row while the ceremony held it, which is only reachable with the ceremony's
		// shared acquisition removed.
		deletion.requireBlocked(t)

		// THE INSERT COMES AFTER THE DELETION HAS ARRIVED. Inserting before it proves nothing: the
		// ceremony would hold every lock it will ever want before the other party asked for
		// anything, and the case would pass against an unordered deletion too.
		code, err := mintCode(db, tx, f.doomed, f.user, f.session.SessionIdentifier)
		require.NoError(t, err, "the ceremony's insert must not be chosen as a deadlock victim")

		deletion.requireStillWaiting(t)
		require.NoError(t, db.CommitTransaction(tx), "committing the ceremony")
		require.NoError(t, deletion.await(t),
			"the deletion must wait for the ceremony and then commit, not deadlock with it")

		// The ceremony won legitimately, so its code existed; the deletion then removed it by
		// cascade, along with everything else of that client's.
		stored, err := db.GetCodeById(nil, code.Id)
		require.NoError(t, err, "reloading the code the ceremony minted")
		assert.Nil(t, stored, "a code of a client that has just been deleted goes with it")
		f.assertDoomedClientGone(t)

		// The survivor is untouched, which is what stops "everything is gone" reading as success.
		assertTokenRevokedOn(t, db, f.survivorToken.Id, false, "the surviving client's token")
		assertCodeRevokedOn(t, db, f.survivorCode.Id, false, "the surviving client's code")
	})

	t.Run("the deletion goes first and the ceremony waits, then refuses", func(t *testing.T) {
		f := newClientDeleteFixtureOn(t, db)

		tx, err := db.BeginTransaction()
		require.NoError(t, err, "opening the deletion's transaction")
		defer func() { _ = db.RollbackTransaction(tx) }()

		require.NoError(t, db.DeleteClient(tx, f.doomed.Id), "DeleteClient on the held transaction")

		ceremony := goBlocked(t, "the ceremony", tx, func(reached func()) issuanceOutcome {
			otherTx, err := other.BeginTransaction()
			if err != nil {
				reached()
				return issuanceOutcome{err: err}
			}
			defer func() { _ = other.RollbackTransaction(otherTx) }()
			reached()
			return issuanceStatements(other, otherTx, f.doomed, f.user, f.session.SessionIdentifier)
		})

		ceremony.requireBlocked(t)
		ceremony.requireStillWaiting(t)
		require.NoError(t, db.CommitTransaction(tx), "committing the deletion")

		outcome := ceremony.await(t)

		// The ceremony waited, then read its answer AFTER the wait, so it found no client and
		// refused. This is the failure that used to be a nil dereference: with the shared
		// acquisition, losing this race is a reliable schedule rather than a narrow one, so the
		// refusal has to be an answer (#248 part 5).
		requireNotDeadlock(t, outcome.err, "the ceremony")
		require.ErrorIs(t, outcome.err, oauth.ErrIssuingClientGone,
			"a ceremony that waited out a deletion of its own client must refuse rather than panic")
		assert.Nil(t, outcome.code, "and must write no code at all")

		f.assertDoomedClientGone(t)
	})
}

// =============================================================================
// GATE 3: two overlapping bumps with stale association lists.
//
// BumpUserSession decides insert-versus-update from a list read BEFORE its transaction opens, so
// two bumps for the same session and client can both read "not associated". The first inserts and
// commits, a deletion then discovers that association, and the second bump arrives with its stale
// list and attempts the duplicate insert. Without #249's unique constraint that insert is
// accepted, so the case is reachable and must not cycle.
// =============================================================================

func TestClientDelete_TwoBumpsWithStaleListsDoNotCycle(t *testing.T) {
	other := secondDatabase(t)

	f := newClientDeleteFixture(t)
	joiner := createTestUserSession(t, f.user.Id)

	// Both bumps read their list before either writes, which is the stale state.
	first, err := database.BeginTransaction()
	require.NoError(t, err, "opening the first bump's transaction")
	defer func() { _ = database.RollbackTransaction(first) }()
	require.NoError(t, insertAssociation(database, first, joiner.Id, f.doomed.Id, true),
		"the first bump takes the client row and inserts")

	deletion := goBlocked(t, "the client deletion", first, func(reached func()) error {
		reached()
		return other.DeleteClient(nil, f.doomed.Id)
	})
	deletion.requireBlocked(t)
	deletion.requireStillWaiting(t)
	require.NoError(t, database.CommitTransaction(first), "committing the first bump")

	// The second bump, with its stale list, arriving while the deletion runs. Whichever order the
	// engine settles on, neither may be aborted over a lock.
	secondDone := make(chan error, 1)
	go func() {
		tx, err := other.BeginTransaction()
		if err != nil {
			secondDone <- err
			return
		}
		defer func() { _ = other.RollbackTransaction(tx) }()
		if err := insertAssociation(other, tx, joiner.Id, f.doomed.Id, true); err != nil {
			secondDone <- err
			return
		}
		secondDone <- other.CommitTransaction(tx)
	}()

	require.NoError(t, deletion.await(t), "the deletion must not be aborted over a lock")

	select {
	case err := <-secondDone:
		// It legitimately fails when it lands after the deletion committed: the foreign key has
		// nothing to point at. What it must not be is a deadlock.
		requireNotDeadlock(t, err, "the second bump")
	case <-time.After(lockWaitCeiling):
		t.Fatal("the second bump never returned")
	}

	f.assertDoomedClientGone(t)
}

// =============================================================================
// GATE 4 AND THE CREDENTIAL PAIR: a password change against a client deletion.
//
// This is the sharpest instance, because the credential operation is the party that loses when
// the cycle forms: the password does not change, the session it was ending survives, and the
// token it was revoking stays valid. The pause point is the one the review named: the credential
// change holds the users row and has deleted its session, so it holds that session's association
// rows, and the deletion holds the client exclusively and is waiting to read them. The revocation
// then updates a refresh token of that client, which is where the shared clients lock used to be
// taken without any statement naming it.
// =============================================================================

func TestLockOrder_ClientDeleteAgainstCredentialSweep(t *testing.T) {
	runClientDeleteAgainstCredentialSweep(t, database, secondDatabase(t))
}

// TestLockOrder_ClientDeleteAgainstCredentialSweep_RCSI is the credential pair against a SQL
// Server database with READ_COMMITTED_SNAPSHOT on (#139 stage 8).
//
// This is one of the four pairs where the deletion's ASSOCIATION READ is what meets the other
// party, rather than its first statement. In "the password change goes first" the deletion
// acquires the client row unopposed and then reads user_session_clients while the credential
// transaction holds those rows, which is precisely the read RCSI stops from blocking. Where the
// deletion comes to rest therefore differs between the two configurations, and only a passing
// schedule says the order still holds when it rests later.
func TestLockOrder_ClientDeleteAgainstCredentialSweep_RCSI(t *testing.T) {
	f := rcsiDatabase(t)
	runClientDeleteAgainstCredentialSweep(t, f.primary, f.secondary)
}

func runClientDeleteAgainstCredentialSweep(t *testing.T, db data.Database, other data.Database) {
	t.Run("the password change goes first and the deletion waits", func(t *testing.T) {
		f := newClientDeleteFixtureOn(t, db)

		tx, err := db.BeginTransaction()
		require.NoError(t, err, "opening the password change's transaction")
		defer func() { _ = db.RollbackTransaction(tx) }()

		// Stopped after the users write and the session delete, holding the association rows by
		// cascade, and BEFORE the grant sweep. That is the interleaving the cycle needs.
		require.NoError(t, changePassword(f.user)(tx), "the password write")
		_, err = db.IncrementUserAuthStateGeneration(tx, f.user.Id)
		require.NoError(t, err, "the generation advance")
		require.NoError(t, sweepSessionBlock(database, tx, f.user.Id), "the sweep's session block")

		deletion := goBlocked(t, "the client deletion", tx, func(reached func()) error {
			reached()
			return other.DeleteClient(nil, f.doomed.Id)
		})
		deletion.requireBlocked(t)

		// THE GRANT SWEEP COMES AFTER THE DELETION HAS ARRIVED, because it is the statement that
		// closes the cycle. With RefreshToken's foreign keys untagged, this UPDATE puts client_id
		// in its SET list, SQL Server re-checks the reference and takes a shared clients lock, and
		// the deletion holding that row exclusively while waiting for these association rows is
		// the other half.
		require.NoError(t, revokeSessionGrants(database, tx, f.session.SessionIdentifier),
			"the credential sweep's grant revocation must not be chosen as a deadlock victim: "+
				"losing this one means the password does not change and the session survives")

		deletion.requireStillWaiting(t)
		require.NoError(t, db.CommitTransaction(tx), "committing the password change")
		require.NoError(t, deletion.await(t),
			"the deletion must wait for the password change and then commit, not deadlock with it")

		// The credential operation did all of its work, which is the point of it not being the
		// victim.
		reloaded, err := db.GetUserById(nil, f.user.Id)
		require.NoError(t, err, "reloading the user")
		require.NotNil(t, reloaded)
		assert.Equal(t, f.user.PasswordHash, reloaded.PasswordHash, "the password change committed")
		assertSessionGoneOn(t, db, f.session.Id, "the session the password change ended")
		assertTokenRevokedOn(t, db, f.survivorToken.Id, true, "the surviving client's token the sweep revoked")

		f.assertDoomedClientGone(t)
	})

	t.Run("the deletion goes first and the password change waits", func(t *testing.T) {
		f := newClientDeleteFixtureOn(t, db)

		tx, err := db.BeginTransaction()
		require.NoError(t, err, "opening the deletion's transaction")
		defer func() { _ = db.RollbackTransaction(tx) }()

		require.NoError(t, db.DeleteClient(tx, f.doomed.Id), "DeleteClient on the held transaction")

		sweep := goBlocked(t, "the password change", tx, func(reached func()) sweepOutcome {
			reached()
			result, err := handlers.RevokeUserAuthStateTx(other, f.user.Id, "", changePassword(f.user))
			return sweepOutcome{result: result, err: err}
		})

		sweep.requireBlocked(t)
		sweep.requireStillWaiting(t)
		require.NoError(t, db.CommitTransaction(tx), "committing the deletion")

		outcome := sweep.await(t)
		require.NoError(t, outcome.err,
			"the password change must wait for the deletion and then commit, not deadlock with it")

		assert.Contains(t, outcome.result.TerminatedSessionIdentifiers, f.session.SessionIdentifier,
			"the sweep still ends the session it was there to end")
		assertSessionGoneOn(t, db, f.session.Id, "the session the password change ended")
		assertTokenRevokedOn(t, db, f.survivorToken.Id, true, "the surviving client's token")
		f.assertDoomedClientGone(t)
	})
}

// revokeSessionGrants issues revokeRefreshTokens' statements for one session on the caller's
// transaction: read the session's tokens, mark each live one revoked. Written out here for the
// reason replayResponse is, and split from the session block above it so a subtest can let the
// other party arrive in between.
func revokeSessionGrants(db data.Database, tx *sql.Tx, sessionIdentifier string) error {
	tokens, err := db.GetRefreshTokensBySessionIdentifier(tx, sessionIdentifier)
	if err != nil {
		return err
	}
	for _, rt := range tokens {
		if rt.Revoked {
			continue
		}
		rt.Revoked = true
		if err := db.UpdateRefreshToken(tx, rt); err != nil {
			return err
		}
	}
	return nil
}

// =============================================================================
// GATE 5: a bump for client A against a deletion of client B, on a session associated with both.
//
// BumpUserSession writes EVERY association the session has, not only the one the ceremony is for,
// while its shared acquisition covers only that one client. With UserSessionClient's keys untagged
// that write re-checks B's foreign key on SQL Server and takes a shared lock on B's row, which the
// deletion is holding exclusively while it waits for this session. Cycle.
// =============================================================================

func TestLockOrder_ClientDeleteAgainstBumpForAnotherClient(t *testing.T) {
	if dbType() == "sqlite" || dbType() == "" {
		t.Skip("SQLite has one writer, so the bump's UPDATE cannot run at all while another connection holds a write; the pair cannot overlap there in production either, for the reason TestLockOrder_IssuanceAgainstSessionBump states")
	}
	other := secondDatabase(t)

	f := newClientDeleteFixture(t)

	tx, err := database.BeginTransaction()
	require.NoError(t, err, "opening the deletion's transaction")
	defer func() { _ = database.RollbackTransaction(tx) }()

	require.NoError(t, database.AcquireClientRow(tx, f.doomed.Id),
		"the deletion takes the doomed client's row exclusively")

	// The real bump, for the SURVIVOR, on a session that also names the doomed client. It is the
	// association loop that used to reach the doomed client's row.
	bump := goBlocked(t, "the session bump", tx, func(reached func()) error {
		manager := user.NewUserSessionManager(nil, nil, "", other)
		reached()
		_, err := manager.BumpUserSession(bumpRequest(), f.session.SessionIdentifier, f.survivor.Id,
			"pwd", enums.AcrLevel1.String())
		return err
	})

	// The bump must RETURN while the deletion still holds the doomed client's row. A bump that
	// needed that row could not, which is exactly what the untagged keys made it need.
	require.NoError(t, bump.await(t),
		"a bump for one client must not need the row of another client the session happens to name")

	// And then the deletion completes on top of it.
	require.NoError(t, database.CommitTransaction(tx), "releasing the deletion's acquisition")
	require.NoError(t, database.DeleteClient(nil, f.doomed.Id), "the deletion itself")
	f.assertDoomedClientGone(t)

	assert.Len(t, associationsOf(t, f.survivor.Id), 1,
		"the bump's own association survives the deletion of the other client")
}

// =============================================================================
// GATE 6: DeleteClient's cascade takes no users lock.
//
// Expected safe, because a foreign key parent is locked for a child INSERT or UPDATE and not for a
// DELETE, but expectation is not measurement. If it did, this transaction would want users below
// clients while every credential operation wants users above everything, and the rule would be
// broken by the very site this stage added.
// =============================================================================

func TestClientDelete_TakesNoUsersLock(t *testing.T) {
	if dbType() == "sqlite" || dbType() == "" {
		t.Skip("SQLite serializes every writer against every other, so it cannot tell 'this transaction wants the users row' from 'this transaction wants to write at all'; the question only has an answer on a row-locking engine")
	}
	other := secondDatabase(t)

	f := newClientDeleteFixture(t)

	tx, err := database.BeginTransaction()
	require.NoError(t, err, "opening the users-row holder's transaction")
	defer func() { _ = database.RollbackTransaction(tx) }()

	require.NoError(t, database.AcquireUserRow(tx, f.user.Id),
		"a credential operation holds the users row of the account whose session names this client")

	// The deletion must RUN TO COMPLETION while that row is held. Anything it wants on users would
	// stop it here.
	deletion := goBlocked(t, "the client deletion", tx, func(reached func()) error {
		reached()
		return other.DeleteClient(nil, f.doomed.Id)
	})

	require.NoError(t, deletion.await(t),
		"DeleteClient must not want the users row of a session's owner: its cascade DELETEs children rather than inserting or updating them")

	f.assertDoomedClientGone(t)
}

// =============================================================================
// GATE 7 AND THE FRESH-SESSION PAIR: users and clients in the same order everywhere.
//
// The cycle review reproduced on MySQL, three parties:
//
//	issuance                holds the users row, waits for the client behind the queued deletion
//	fresh session creation  holds the client row shared, waits for the users row behind issuance
//	client deletion         queued exclusively on the client, waits for the fresh session
//
// Nothing is upgraded and no two shared holders ever conflict; the cycle exists because lock
// queues are FAIR, so once the deletion's exclusive request is queued behind a shared holder, a
// later shared request queues behind the DELETION rather than joining the holder. The remedy is
// that StartNewUserSession takes the users row BEFORE the shared client row, so it never holds
// half of what the issuance wants.
//
// WHAT THIS TEST ASSERTS, and why it is the property rather than the schedule. Building all three
// waits at once needs the fresh session's transaction held open part way, which
// StartNewUserSession does not allow: it owns and commits its own transaction. So the test asserts
// the thing that makes the cycle impossible, which is stronger and simpler than the cycle itself:
// a fresh session creation blocked at the top of the order is holding NO client lock, so a client
// deletion arriving behind it runs straight through.
//
// That is exactly what inverts under the mutation. With the leading AcquireUserRow removed, the
// creation takes the shared client row first and blocks on the users row while holding it, and the
// deletion then cannot get past its exclusive acquisition: it stops, and this test fails on the
// line that requires it to have completed.
//
// It is driven through the REAL StartNewUserSession rather than through equivalent locking reads.
// Stand-ins are the right tool for establishing that a cycle exists, which is the probe's job; a
// committed test has a second job, which is to establish that PRODUCTION takes these locks in this
// order, and a test built from stand-ins keeps passing after somebody removes the acquisition from
// the manager.
// =============================================================================

func TestLockOrder_ClientDeleteAgainstFreshSession(t *testing.T) {
	if dbType() == "sqlite" || dbType() == "" {
		t.Skip("SQLite serializes every writer, so a creation blocked at the top of the order is indistinguishable there from one blocked anywhere else; the authserver also builds one handle, so these never overlap in production")
	}

	other := secondDatabase(t)

	f := newClientDeleteFixture(t)
	signingIn := createTestUser(t)

	// The foreground stands in for an authorization ceremony for the SAME user: it holds the users
	// row, which is the top of the order, and it is what the fresh session creation has to queue
	// behind.
	tx, err := database.BeginTransaction()
	require.NoError(t, err, "opening the ceremony's transaction")
	defer func() { _ = database.RollbackTransaction(tx) }()
	require.NoError(t, database.AcquireUserRow(tx, signingIn.Id), "the ceremony takes the users row")

	creation := goBlocked(t, "the fresh session creation", tx, func(reached func()) error {
		// A real cookie store, because StartNewUserSession writes the identifier into the browser
		// session on its way out. Nothing here reads it back; what this party is for is the
		// statements its transaction puts on the connection.
		manager := user.NewUserSessionManager(nil, sessions.NewCookieStore([]byte(gofakeit.LetterN(32))),
			"test-session", other)
		reached()
		_, err := manager.StartNewUserSession(httptest.NewRecorder(), bumpRequest(), signingIn.Id,
			f.doomed.Id, "pwd", enums.AcrLevel1.String(), 0, nil)
		return err
	})

	// It must be waiting, and it must be waiting at the USERS row, holding nothing below it.
	creation.requireBlocked(t)

	// THE ASSERTION. The deletion arrives while the creation is blocked and must run to
	// completion. It can only do that if the creation holds no lock on the client row, which is
	// the whole of what the leading AcquireUserRow buys. With that acquisition removed the
	// creation is sitting on the shared client lock instead and this call cannot finish.
	require.NoError(t, other.DeleteClient(nil, f.doomed.Id),
		"a client deletion must not be held up by a sign-in that is queued at the top of the lock order: "+
			"a creation blocked on the users row is holding no client lock, and taking the client row "+
			"first is the MySQL three-party deadlock this order exists to prevent")

	creation.requireStillWaiting(t)
	require.NoError(t, database.CommitTransaction(tx), "committing the ceremony")

	// The creation then loses the race, which is the correct outcome arriving in an unfriendly
	// shape: it is signing in to a client that no longer exists. What matters is that it fails
	// WHOLE, leaving no session row behind for a sign-in that never completed.
	err = creation.await(t)
	requireNotDeadlock(t, err, "the fresh session creation")
	require.Error(t, err,
		"a sign-in for a client deleted while it waited must fail its association insert rather than half-complete")
	assertNoOrphanSessionFor(t, signingIn.Id)

	f.assertDoomedClientGone(t)
}

// assertNoOrphanSessionFor requires that a fresh session creation which failed its association
// insert left nothing behind. The session row and the association row are written in one
// transaction precisely so that half of a sign-in cannot survive.
func assertNoOrphanSessionFor(t *testing.T, userId int64) {
	t.Helper()
	sessions, err := database.GetUserSessionsByUserId(nil, userId)
	require.NoError(t, err, "reading the sessions of the user whose sign-in failed")
	assert.Empty(t, sessions,
		"a creation that failed its association insert must roll back whole, leaving no session row")
}

// =============================================================================
// THE REMAINING PAIRS. Each is a session-side transaction of this branch against a client
// deletion, in both orderings, asserting its own outcome rather than one blanket claim.
// =============================================================================

func TestLockOrder_ClientDeleteAgainstTermination(t *testing.T) {
	runClientDeleteAgainstTermination(t, database, secondDatabase(t))
}

// TestLockOrder_ClientDeleteAgainstTermination_RCSI is the termination pair under RCSI, for the
// reason the credential pair above states: the deletion meets this party at its association read.
func TestLockOrder_ClientDeleteAgainstTermination_RCSI(t *testing.T) {
	f := rcsiDatabase(t)
	runClientDeleteAgainstTermination(t, f.primary, f.secondary)
}

func runClientDeleteAgainstTermination(t *testing.T, db data.Database, other data.Database) {
	t.Run("the termination goes first and the deletion waits", func(t *testing.T) {
		f := newClientDeleteFixtureOn(t, db)

		tx, err := db.BeginTransaction()
		require.NoError(t, err, "opening the termination's transaction")
		defer func() { _ = db.RollbackTransaction(tx) }()

		// Stopped after the session delete, so it holds the association rows by cascade, and
		// before the grant sweep, which is the statement that used to reach the clients row.
		require.NoError(t, db.DeleteUserSession(tx, f.session.Id), "the termination's first statement")
		_, err = db.RevokeCodesBySessionIdentifier(tx, f.session.SessionIdentifier)
		require.NoError(t, err, "the termination's code sweep")

		deletion := goBlocked(t, "the client deletion", tx, func(reached func()) error {
			reached()
			return other.DeleteClient(nil, f.doomed.Id)
		})
		deletion.requireBlocked(t)

		require.NoError(t, revokeSessionGrants(database, tx, f.session.SessionIdentifier),
			"the termination's grant sweep must not be chosen as a deadlock victim")

		deletion.requireStillWaiting(t)
		require.NoError(t, db.CommitTransaction(tx), "committing the termination")
		require.NoError(t, deletion.await(t),
			"the deletion must wait for the termination and then commit, not deadlock with it")

		assertSessionGoneOn(t, db, f.session.Id, "the terminated session")
		assertCodeRevokedOn(t, db, f.survivorCode.Id, true, "the surviving client's code the termination revoked")
		assertTokenRevokedOn(t, db, f.survivorToken.Id, true, "the surviving client's token the termination revoked")
		f.assertDoomedClientGone(t)
	})

	t.Run("the deletion goes first and the termination waits", func(t *testing.T) {
		f := newClientDeleteFixtureOn(t, db)

		tx, err := db.BeginTransaction()
		require.NoError(t, err, "opening the deletion's transaction")
		defer func() { _ = db.RollbackTransaction(tx) }()

		require.NoError(t, db.DeleteClient(tx, f.doomed.Id), "DeleteClient on the held transaction")

		termination := goBlocked(t, "the termination", tx, func(reached func()) error {
			reached()
			_, err := handlers.TerminateUserSessionTx(other, f.session)
			return err
		})

		termination.requireBlocked(t)
		termination.requireStillWaiting(t)
		require.NoError(t, db.CommitTransaction(tx), "committing the deletion")
		require.NoError(t, termination.await(t),
			"the termination must wait for the deletion and then commit, not deadlock with it")

		assertSessionGoneOn(t, db, f.session.Id, "the terminated session")
		assertCodeRevokedOn(t, db, f.survivorCode.Id, true, "the surviving client's code")
		assertTokenRevokedOn(t, db, f.survivorToken.Id, true, "the surviving client's token")
		f.assertDoomedClientGone(t)
	})
}

func TestLockOrder_ClientDeleteAgainstDeleteUser(t *testing.T) {
	runClientDeleteAgainstDeleteUser(t, database, secondDatabase(t))
}

// TestLockOrder_ClientDeleteAgainstDeleteUser_RCSI is the user-delete pair under RCSI. Same
// reason, and one more: DeleteUser is the other transaction on the branch that discovers rows and
// then acquires them, so both parties here have a read RCSI changes.
func TestLockOrder_ClientDeleteAgainstDeleteUser_RCSI(t *testing.T) {
	f := rcsiDatabase(t)
	runClientDeleteAgainstDeleteUser(t, f.primary, f.secondary)
}

func runClientDeleteAgainstDeleteUser(t *testing.T, db data.Database, other data.Database) {
	t.Run("the user delete goes first and the client delete waits", func(t *testing.T) {
		f := newClientDeleteFixtureOn(t, db)

		tx, err := db.BeginTransaction()
		require.NoError(t, err, "opening the user delete's transaction")
		defer func() { _ = db.RollbackTransaction(tx) }()

		require.NoError(t, db.DeleteUser(tx, f.user.Id), "DeleteUser on the held transaction")

		deletion := goBlocked(t, "the client deletion", tx, func(reached func()) error {
			reached()
			return other.DeleteClient(nil, f.doomed.Id)
		})

		deletion.requireBlocked(t)
		deletion.requireStillWaiting(t)
		require.NoError(t, db.CommitTransaction(tx), "committing the user delete")
		require.NoError(t, deletion.await(t),
			"the client delete must wait for the user delete and then commit, not deadlock with it")

		gone, err := db.GetUserById(nil, f.user.Id)
		require.NoError(t, err, "reloading the deleted user")
		assert.Nil(t, gone, "the user is gone")

		// The surviving client's grants were DELETED rather than revoked, which is what deleting a
		// user means and what distinguishes this pair's outcome from the sweep's.
		token, err := db.GetRefreshTokenById(nil, f.survivorToken.Id)
		require.NoError(t, err, "reloading the surviving client's token")
		assert.Nil(t, token, "deleting a user removes its grants rather than revoking them")
		f.assertDoomedClientGone(t)
	})

	t.Run("the client delete goes first and the user delete waits", func(t *testing.T) {
		f := newClientDeleteFixtureOn(t, db)

		tx, err := db.BeginTransaction()
		require.NoError(t, err, "opening the client delete's transaction")
		defer func() { _ = db.RollbackTransaction(tx) }()

		require.NoError(t, db.DeleteClient(tx, f.doomed.Id), "DeleteClient on the held transaction")

		deletion := goBlocked(t, "DeleteUser", tx, func(reached func()) error {
			reached()
			return other.DeleteUser(nil, f.user.Id)
		})

		deletion.requireBlocked(t)
		deletion.requireStillWaiting(t)
		require.NoError(t, db.CommitTransaction(tx), "committing the client delete")
		require.NoError(t, deletion.await(t),
			"the user delete must wait for the client delete and then commit, not deadlock with it")

		gone, err := db.GetUserById(nil, f.user.Id)
		require.NoError(t, err, "reloading the deleted user")
		assert.Nil(t, gone, "the user is gone")
		f.assertDoomedClientGone(t)
	})
}

func TestLockOrder_ClientDeleteAgainstReplayResponse(t *testing.T) {
	runClientDeleteAgainstReplayResponse(t, database, secondDatabase(t))
}

// TestLockOrder_ClientDeleteAgainstReplayResponse_RCSI is the replay pair under RCSI, for the
// reason the credential pair above states.
func TestLockOrder_ClientDeleteAgainstReplayResponse_RCSI(t *testing.T) {
	f := rcsiDatabase(t)
	runClientDeleteAgainstReplayResponse(t, f.primary, f.secondary)
}

func runClientDeleteAgainstReplayResponse(t *testing.T, db data.Database, other data.Database) {
	t.Run("the replay goes first and the deletion waits", func(t *testing.T) {
		f := newClientDeleteFixtureOn(t, db)

		tx, err := db.BeginTransaction()
		require.NoError(t, err, "opening the replay's transaction")
		defer func() { _ = db.RollbackTransaction(tx) }()

		live, err := db.AcquireUserSessionRow(tx, f.session.SessionIdentifier)
		require.NoError(t, err, "the replay takes the session row, which is its first statement")
		require.True(t, live)

		deletion := goBlocked(t, "the client deletion", tx, func(reached func()) error {
			reached()
			return other.DeleteClient(nil, f.doomed.Id)
		})
		deletion.requireBlocked(t)

		// The rest of the replay, after the deletion has arrived: the grant sweep and #77's
		// conditional teardown.
		require.NoError(t, revokeSessionGrants(database, tx, f.session.SessionIdentifier),
			"the replay's grant sweep must not be chosen as a deadlock victim")
		require.NoError(t, db.DeleteUserSession(tx, f.session.Id),
			"#77's teardown, which runs because the sweep revoked something")

		deletion.requireStillWaiting(t)
		require.NoError(t, db.CommitTransaction(tx), "committing the replay")
		require.NoError(t, deletion.await(t),
			"the deletion must wait for the replay and then commit, not deadlock with it")

		assertSessionGoneOn(t, db, f.session.Id, "the session the replay tore down")
		assertTokenRevokedOn(t, db, f.survivorToken.Id, true, "the surviving client's token the replay revoked")
		f.assertDoomedClientGone(t)
	})

	t.Run("the deletion goes first and the replay waits", func(t *testing.T) {
		f := newClientDeleteFixtureOn(t, db)

		tx, err := db.BeginTransaction()
		require.NoError(t, err, "opening the deletion's transaction")
		defer func() { _ = db.RollbackTransaction(tx) }()

		require.NoError(t, db.DeleteClient(tx, f.doomed.Id), "DeleteClient on the held transaction")

		type replayOutcome struct {
			live bool
			err  error
		}
		replay := goBlocked(t, "the replay response", tx, func(reached func()) replayOutcome {
			otherTx, err := other.BeginTransaction()
			if err != nil {
				reached()
				return replayOutcome{err: err}
			}
			defer func() { _ = other.RollbackTransaction(otherTx) }()
			reached()
			live, err := replayResponse(other, otherTx, f.session.SessionIdentifier)
			if err != nil {
				return replayOutcome{live: live, err: err}
			}
			return replayOutcome{live: live, err: other.CommitTransaction(otherTx)}
		})

		replay.requireBlocked(t)
		replay.requireStillWaiting(t)
		require.NoError(t, db.CommitTransaction(tx), "committing the deletion")

		outcome := replay.await(t)
		require.NoError(t, outcome.err,
			"the replay must wait for the deletion and then commit, not deadlock with it")
		assert.True(t, outcome.live, "the session outlives a deletion of one of its clients")

		assertSessionGoneOn(t, db, f.session.Id, "the session the replay tore down after waiting")
		assertTokenRevokedOn(t, db, f.survivorToken.Id, true, "the surviving client's token")
		f.assertDoomedClientGone(t)
	})
}
