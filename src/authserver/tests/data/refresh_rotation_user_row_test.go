package datatests

import (
	"context"
	"database/sql"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/data"
	"github.com/leodip/goiabada/authserver/internal/issuance"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/authserver/internal/revocation"
	"github.com/leodip/goiabada/core/logging/logtest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A refresh rotation takes the token's user row first, and a credential change takes the same row
// first through its write and its generation increment, so the two serialize and a rotation's child
// is never left a generation behind the user (#131, #437). What a mock cannot show is that the row is
// really held, on each engine, and that both orders of the pair, and the overlap of the two, end in
// the same place; this file is that proof. The rotation and the change are the real
// IssueRefreshTokenGrant and revocation.RevokeUserAuthStateTx.
//
// The invariant is the one the issue states: a refresh that succeeds never hands out a child the next
// refresh refuses. A child is refused by the validator when its generation is behind the user's, so
// the assertion is that no live member of the family is behind the user's generation once both have
// committed, plus what each shape is owed: a session-bound or an offline grant keeps a live child at
// the user's new generation, because the change preserved its session, and a password grant, which
// has no session to preserve, ends with no live token.

// AcquireUserRow's contract. It writes nothing a reader can observe, so what there is to pin is when
// it refuses and what it leaves alone: the column the admin console shows as "Last updated at", and
// the generation it assigns to itself.
func TestAcquireUserRow(t *testing.T) {
	user := createTestUser(t)
	before, err := database.GetUserById(context.Background(), nil, user.Id)
	require.NoError(t, err)
	require.NotNil(t, before)

	tx := beginTx(t)
	require.NoError(t, database.AcquireUserRow(context.Background(), tx, user.Id))
	require.NoError(t, database.CommitTransaction(context.Background(), tx))

	after, err := database.GetUserById(context.Background(), nil, user.Id)
	require.NoError(t, err)
	require.NotNil(t, after)
	assert.True(t, before.UpdatedAt.Time.Equal(after.UpdatedAt.Time),
		"a refresh is not an edit of the account: updated_at is %v and was %v", after.UpdatedAt.Time, before.UpdatedAt.Time)
	assert.Equal(t, before.AuthStateGeneration, after.AuthStateGeneration, "assigned to itself, so it does not move")

	t.Run("a user that is not there is not an error", func(t *testing.T) {
		tx := beginTx(t)
		assert.NoError(t, database.AcquireUserRow(context.Background(), tx, user.Id+1_000_000))
	})

	t.Run("an id of 0 is a caller's bug", func(t *testing.T) {
		tx := beginTx(t)
		assert.Error(t, database.AcquireUserRow(context.Background(), tx, 0))
	})

	t.Run("without a transaction the statement would autocommit and release the row", func(t *testing.T) {
		assert.Error(t, database.AcquireUserRow(context.Background(), nil, user.Id))
	})
}

func TestAcquireUserRow_RefusesAnAlreadyCancelledContext(t *testing.T) {
	user := createTestUser(t)

	tx := beginTx(t)
	err := database.AcquireUserRow(cancelled(), tx, user.Id)

	require.Error(t, err, "a refusal, not a silent acquisition of nothing")
	assert.ErrorIs(t, err, context.Canceled)
}

// The acquisition holds the row until its transaction ends: a writer of the user's row on another
// connection waits for it. Without this, the rotation would not stop a credential change from
// writing the row between the claim and the insert, which is the whole of #131. The statement
// assigns a column to itself, and whether an engine takes a row lock for a write that changes
// nothing is the engine's to say, so this runs on every engine that can overlap.
func TestAcquireUserRow_HoldsTheRowUntilTheTransactionEnds(t *testing.T) {
	skipWhereTransactionsCannotOverlap(t)
	other := secondDatabase(t)

	user := createTestUserOn(t, database)
	holder := beginTx(t)
	require.NoError(t, database.AcquireUserRow(context.Background(), holder, user.Id))

	writer := goBlocked(t, "a credential write", holder, func(reached func()) error {
		tx, err := other.BeginTransaction(context.Background())
		if err != nil {
			return err
		}
		defer func() { _ = other.RollbackTransaction(context.Background(), tx) }()
		reached()
		if err := other.SetUserPasswordHash(context.Background(), tx, user.Id, "hash-written-behind-the-acquisition"); err != nil {
			return err
		}
		return other.CommitTransaction(context.Background(), tx)
	})
	writer.requireBlocked(t)
	writer.requireStillWaiting(t)

	require.NoError(t, database.CommitTransaction(context.Background(), holder))
	require.NoError(t, writer.await(t), "the write goes through once the holder commits")
}

// And the converse: the acquisition waits for a writer of the row. This is the order in which a
// credential change arrives first and the rotation queues behind it, so the rotation then reads its
// token as the change left it.
func TestAcquireUserRow_WaitsForAWriterOfTheRow(t *testing.T) {
	skipWhereTransactionsCannotOverlap(t)
	other := secondDatabase(t)

	user := createTestUserOn(t, database)
	writer := beginTx(t)
	require.NoError(t, database.SetUserPasswordHash(context.Background(), writer, user.Id, "hash-held-by-the-writer"))

	acquiring := goBlocked(t, "the acquisition", writer, func(reached func()) error {
		tx, err := other.BeginTransaction(context.Background())
		if err != nil {
			return err
		}
		defer func() { _ = other.RollbackTransaction(context.Background(), tx) }()
		reached()
		return other.AcquireUserRow(context.Background(), tx, user.Id)
	})
	acquiring.requireBlocked(t)
	acquiring.requireStillWaiting(t)

	require.NoError(t, database.CommitTransaction(context.Background(), writer))
	require.NoError(t, acquiring.await(t), "the acquisition goes through once the writer commits")
}

func userGenerationOn(t *testing.T, db data.Database, userId int64) int64 {
	t.Helper()

	user, err := db.GetUserById(context.Background(), nil, userId)
	require.NoError(t, err)
	require.NotNil(t, user)
	return user.AuthStateGeneration
}

// changeTheUsersPassword is a credential change as the account page makes it: the password write and
// the revocation of every credential the user authenticated under in one transaction, preserving the
// caller's own session. A password grant's family has no session, so nothing is preserved for it.
// pause, when set, runs after the password write, holding the user's row.
func changeTheUsersPassword(ctx context.Context, db data.Database, f *family, pause func(tx *sql.Tx)) error {
	preserved := ""
	if !f.ropc {
		preserved = f.code.SessionIdentifier
	}
	_, err := revocation.RevokeUserAuthStateTx(ctx, db, f.user.Id, preserved, func(tx *sql.Tx) error {
		if err := db.SetUserPasswordHash(ctx, tx, f.user.Id, "hash-after-the-credential-change"); err != nil {
			return err
		}
		if pause != nil {
			pause(tx)
		}
		return nil
	})
	return err
}

// rotate redeems the presented input on db, to the end.
func rotate(ctx context.Context, db data.Database, input *issuance.RefreshTokenGrantInput) rotationResult {
	response, _, err := refreshIssuerOn(db).IssueRefreshTokenGrant(ctx, rotationSettings(), input)
	result := rotationResult{err: err}
	if response != nil {
		result.response = response.RefreshToken
	}
	return result
}

// requireOutcome is what a rotation and a credential change must leave behind however they were
// ordered, given that the change took the user from generation before to before+1. rotationFirst says
// which of the two committed first: it matters only to a password grant, whose change either found
// the child and revoked it, or revoked the token first and left the rotation nothing to claim.
func requireOutcome(t *testing.T, f *family, result rotationResult, before int64, rotationFirst bool) {
	t.Helper()

	userGeneration := userGenerationOn(t, database, f.user.Id)
	require.Equal(t, before+1, userGeneration, "the credential change moved the user one generation on")

	// The property the decision is for, whichever shape and whichever order: nothing the rotation
	// left live is behind the user, so the next refresh does not refuse it.
	var members []*record.RefreshToken
	var err error
	if f.ropc {
		members, err = database.GetRefreshTokensByUserId(context.Background(), nil, f.user.Id)
	} else {
		members, err = database.GetRefreshTokensByCodeId(context.Background(), nil, f.code.Id)
	}
	require.NoError(t, err)
	for _, member := range members {
		if member.Revoked {
			continue
		}
		assert.Equal(t, userGeneration, member.AuthStateGeneration,
			"the live token %s is behind the user's generation: the next refresh would refuse it", member.RefreshTokenJti)
	}

	if !f.ropc {
		require.NoError(t, result.err, "a refresh that preserved its session is not refused by the change")
		child := childOf(t, database, result.response)
		assert.False(t, child.Revoked, "the user's own session keeps working: its child is live")
		assert.Equal(t, userGeneration, child.AuthStateGeneration, "and stamped with the generation the change promoted it to")
		assertTokenRevoked(t, f.live.Id, true, "the presented token, claimed by the rotation")
		assert.Equal(t, 3, f.members(t, database))
		return
	}

	if rotationFirst {
		require.NoError(t, result.err)
		child := childOf(t, database, result.response)
		assert.True(t, child.Revoked, "the change's sweep found the child and revoked it")
		assert.Equal(t, 3, f.members(t, database))
		return
	}
	require.ErrorIs(t, result.err, issuance.ErrRefreshTokenNotClaimed, "the change revoked the token before the rotation could claim it")
	assertTokenRevoked(t, f.live.Id, true, "the presented token, revoked by the change")
	assert.Equal(t, 2, f.members(t, database), "a refused rotation inserted no child")
}

// requireNoDeadlockRerun is the decision's claim that both transactions take the user's row first, so
// the pair cannot deadlock on each other (#131, #301). RunInTransaction would rerun a victim and the
// outcome would still be right, which is why the outcome cannot show it: SQL Server's locking reads
// make the pair collide on the token rows instead, and the rerun then hides that the acquisition is
// missing. A rerun is what says so.
func requireNoDeadlockRerun(t *testing.T, logs *logtest.SlogCapture) {
	t.Helper()

	for _, logRecord := range logs.Records() {
		assert.NotEqual(t, "rerunning a transaction the engine aborted as a deadlock victim", logRecord.Message,
			"the rotation and the credential change serialize on the user's row, so neither is a deadlock victim")
	}
}

var allShapes = []familyShape{sessionBoundFamily, offlineFamily, passwordGrantFamily}

// The rotation commits, then the credential change runs. The change's sweep finds the child, and
// promotes it with its session or revokes it.
func TestRefreshRotation_ARotationThenACredentialChange(t *testing.T) {
	for _, shape := range allShapes {
		t.Run(shape.String(), func(t *testing.T) {
			withRealSigningKeyOn(t, database)
			ctx, cancel := context.WithTimeout(context.Background(), lockWaitCeiling)
			defer cancel()

			f := newFamilyOfShape(t, database, shape)
			before := userGenerationOn(t, database, f.user.Id)

			result := rotate(ctx, database, f.presenting(t, database, f.live.RefreshTokenJti))
			require.NoError(t, result.err)
			require.NoError(t, changeTheUsersPassword(ctx, database, f, nil))

			requireOutcome(t, f, result, before, true)
		})
	}
}

// The credential change commits between the validator's read of the token and the rotation, so the
// rotation arrives with a copy that is a generation behind. A session-bound or offline grant's token
// was promoted and is live: the rotation must stamp its child from the row as the change left it, and
// not from the copy in its hand, or it returns a child the next refresh refuses. A password grant's
// token was revoked: the rotation loses its claim and is refused cleanly (#131).
func TestRefreshRotation_ACredentialChangeBetweenTheValidatorAndTheRotation(t *testing.T) {
	for _, shape := range allShapes {
		t.Run(shape.String(), func(t *testing.T) {
			withRealSigningKeyOn(t, database)
			ctx, cancel := context.WithTimeout(context.Background(), lockWaitCeiling)
			defer cancel()

			f := newFamilyOfShape(t, database, shape)
			before := userGenerationOn(t, database, f.user.Id)

			stale := f.presenting(t, database, f.live.RefreshTokenJti)
			require.NoError(t, changeTheUsersPassword(ctx, database, f, nil))
			result := rotate(ctx, database, stale)

			requireOutcome(t, f, result, before, false)
		})
	}
}

// The rotation holds the user's row, paused at the insert of its child, when a credential change
// starts on another connection. The change's first statement is its write of the same row, so it
// waits; the rotation then commits, and the change resumes to find the child and promote or revoke
// it. Without the rotation's acquisition the two touch no common row until the insert, the change
// goes straight through and sweeps before the child exists, and the child is left live at the old
// generation.
func TestRefreshRotation_ACredentialChangeArrivingWhileARotationHoldsTheRow(t *testing.T) {
	skipWhereTransactionsCannotOverlap(t)

	for _, shape := range allShapes {
		t.Run(shape.String(), func(t *testing.T) {
			other := secondDatabase(t)
			withRealSigningKeyOn(t, database)
			logs := logtest.CaptureSlog(t)
			ctx, cancel := context.WithTimeout(context.Background(), lockWaitCeiling)
			defer cancel()

			f := newFamilyOfShape(t, database, shape)
			before := userGenerationOn(t, database, f.user.Id)
			pause := newPausingInserts(database)
			tx, rotation := startRotation(t, ctx, f, pause)

			change := goBlocked(t, "the credential change", tx, func(reached func()) error {
				reached()
				return changeTheUsersPassword(ctx, other, f, nil)
			})
			change.requireBlocked(t)
			change.requireStillWaiting(t)

			close(pause.release)
			result := <-rotation
			require.NoError(t, change.await(t), "the change commits once the rotation has")

			requireOutcome(t, f, result, before, true)
			requireNoDeadlockRerun(t, logs)
		})
	}
}

// The credential change holds the user's row, parked after its write and before its sweep, when a
// rotation starts on another connection with the copy the validator read before the change. The
// rotation's first statement is its acquisition of the same row, so it waits; the change commits, and
// the rotation resumes to read its token as the change left it.
func TestRefreshRotation_ARotationArrivingWhileACredentialChangeHoldsTheRow(t *testing.T) {
	skipWhereTransactionsCannotOverlap(t)

	for _, shape := range allShapes {
		t.Run(shape.String(), func(t *testing.T) {
			other := secondDatabase(t)
			withRealSigningKeyOn(t, database)
			logs := logtest.CaptureSlog(t)
			ctx, cancel := context.WithTimeout(context.Background(), lockWaitCeiling)
			defer cancel()

			f := newFamilyOfShape(t, database, shape)
			before := userGenerationOn(t, database, f.user.Id)
			stale := f.presenting(t, database, f.live.RefreshTokenJti)

			held := newBarrier(t, "the credential change")
			changed := make(chan error, 1)
			go func() {
				changed <- changeTheUsersPassword(ctx, database, f, held.arriveBefore)
			}()
			changeTx := held.awaitParked(t)

			rotation := goBlocked(t, "the rotation", changeTx, func(reached func()) rotationResult {
				reached()
				return rotate(ctx, other, stale)
			})
			rotation.requireBlocked(t)
			rotation.requireStillWaiting(t)

			held.releaseParked()
			require.NoError(t, awaitWorker(t, "the credential change", changed))
			result := rotation.await(t)

			requireOutcome(t, f, result, before, false)
			requireNoDeadlockRerun(t, logs)
		})
	}
}

// A rotation and a credential change started together, in whatever order the engine happens to run
// them, agree on the child: one the rotation returns is not behind the user's generation. The
// overlaps above force each order; this one leaves the order to the engine, which is what a
// deployment does.
func TestRefreshRotation_ARotationAndACredentialChangeStartedTogetherAgreeOnTheChild(t *testing.T) {
	skipWhereTransactionsCannotOverlap(t)
	other := secondDatabase(t)
	withRealSigningKeyOn(t, database)
	logs := logtest.CaptureSlog(t)
	ctx, cancel := context.WithTimeout(context.Background(), lockWaitCeiling)
	defer cancel()

	f := newFamilyOfShape(t, database, sessionBoundFamily)
	input := f.presenting(t, database, f.live.RefreshTokenJti)

	rotated := make(chan rotationResult, 1)
	changed := make(chan error, 1)
	go func() { rotated <- rotate(ctx, database, input) }()
	go func() { changed <- changeTheUsersPassword(ctx, other, f, nil) }()

	result := awaitWorker(t, "the rotation", rotated)
	require.NoError(t, awaitWorker(t, "the credential change", changed))
	require.NoError(t, result.err, "a session-bound token whose session the change preserved is never refused by it")
	child := childOf(t, database, result.response)
	assert.False(t, child.Revoked)
	assert.Equal(t, userGenerationOn(t, database, f.user.Id), child.AuthStateGeneration,
		"whichever order the engine chose, the child the rotation returned is not behind the user")
	requireNoDeadlockRerun(t, logs)
}
