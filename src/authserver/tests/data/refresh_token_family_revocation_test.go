package datatests

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/leodip/goiabada/authserver/internal/data"
	"github.com/leodip/goiabada/authserver/internal/fake"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Seam of #437 (#132, #259): the revoked-family record's three methods, against the real engines.
//
// The reason this tier owns them. The record is written in the transaction of the revocation it
// records and read by the refresh validator and by a rotation's own transaction, so what the tests
// below pin is what a mock cannot: that the row really goes where the transaction goes, that a
// second record of a family keeps the first reason and time, that the lookup compares the jti as
// exactly what it is (SQL Server pads for `=` under every collation, which is why the data layer
// compares the row it got back against the jti it asked for), that the orphan sweep's NOT EXISTS
// over refresh_tokens means what it says on four engines, and that two overlapping first writes
// leave exactly one creator whichever way the engine settles them.
//
// Run per dialect via: ./run-tests.sh --type data --db <sqlite|mysql|postgres|mssql>

// familyRevocationReason is a reason the column holds: 64 characters is its width.
const familyRevocationReason = "refresh_token_replay"

// newFamilyJti is a family's first jti, with a lower-case prefix so its upper-case spelling is a
// different string, and random so a case can run twice on one database.
func newFamilyJti() string {
	return "fam-" + fake.UUID()
}

// recordFamily records a family that is not yet recorded, and requires that this call wrote it.
func recordFamily(t *testing.T, family string) {
	t.Helper()
	created, err := database.RecordRefreshTokenFamilyRevoked(context.Background(), nil, family, familyRevocationReason)
	require.NoError(t, err, "RecordRefreshTokenFamilyRevoked")
	require.True(t, created, "the family was not recorded, so this call writes it")
}

// familyIsRevoked asks the lookup under test, through the pool.
func familyIsRevoked(t *testing.T, family string) bool {
	t.Helper()
	revoked, err := database.IsRefreshTokenFamilyRevoked(context.Background(), nil, family)
	require.NoError(t, err, "IsRefreshTokenFamilyRevoked")
	return revoked
}

// familyRevocationRow reads the record straight from the table, so an assertion about what was
// kept does not go through the lookup whose comparison is also under test. The jti is inlined
// rather than bound, so this one query needs no per-engine placeholder syntax; it is a value the
// test drew, not caller input.
func familyRevocationRow(t *testing.T, family string) (reason string, revokedAt time.Time, found bool) {
	t.Helper()
	err := rawSQLHandle(t).QueryRowContext(context.Background(), fmt.Sprintf(
		"SELECT reason, revoked_at FROM refresh_token_family_revocations WHERE first_refresh_token_jti = '%s'",
		family)).Scan(&reason, &revokedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return "", time.Time{}, false
	}
	require.NoError(t, err, "read the family's row")
	return reason, revokedAt, true
}

// familyRevocationCount is the number of rows the whole table holds. The tests that assert a
// refusal wrote nothing compare it before and after, and every case in this tier runs in
// sequence, so nothing else moves it in between.
func familyRevocationCount(t *testing.T) int {
	t.Helper()
	var n int
	require.NoError(t, rawSQLHandle(t).QueryRowContext(context.Background(),
		"SELECT COUNT(*) FROM refresh_token_family_revocations").Scan(&n))
	return n
}

func TestRefreshTokenFamilyRevocation_RecordThenRead(t *testing.T) {
	ctx := context.Background()

	t.Run("an unrecorded family reads as not revoked", func(t *testing.T) {
		family := newFamilyJti()

		assert.False(t, familyIsRevoked(t, family), "no record, so the token proceeds")
		_, _, found := familyRevocationRow(t, family)
		assert.False(t, found, "and the read wrote nothing")
	})

	t.Run("the first record creates the row and reports it", func(t *testing.T) {
		family := newFamilyJti()

		created, err := database.RecordRefreshTokenFamilyRevoked(ctx, nil, family, familyRevocationReason)
		require.NoError(t, err)
		assert.True(t, created, "the call that wrote the row is told so")

		reason, revokedAt, found := familyRevocationRow(t, family)
		require.True(t, found, "the row is in the table")
		assert.Equal(t, familyRevocationReason, reason)
		assert.WithinDuration(t, time.Now().UTC(), revokedAt, 30*time.Second, "revoked_at is stamped with the write")
		assert.True(t, familyIsRevoked(t, family), "and the family reads as revoked")
	})

	t.Run("a record of one family leaves another unrecorded", func(t *testing.T) {
		recorded := newFamilyJti()
		bystander := newFamilyJti()
		recordFamily(t, recorded)

		assert.True(t, familyIsRevoked(t, recorded))
		assert.False(t, familyIsRevoked(t, bystander), "a family is revoked by its own jti and no other")
	})
}

// The record is what a replay's containment and a client's switch to public leave behind, and a
// second writer that arrives later must not rewrite it: its first reason and time stay, and the
// call reports false, which is how containment knows it recorded the family without having
// revoked anything itself.
func TestRefreshTokenFamilyRevocation_ASecondRecordKeepsTheFirst(t *testing.T) {
	ctx := context.Background()

	for _, tc := range []struct {
		name         string
		secondReason string
	}{
		{"a second record with another reason", "client_made_public"},
		{"a second record with the same reason", familyRevocationReason},
	} {
		t.Run(tc.name, func(t *testing.T) {
			family := newFamilyJti()
			recordFamily(t, family)
			firstReason, firstAt, found := familyRevocationRow(t, family)
			require.True(t, found)
			require.Equal(t, familyRevocationReason, firstReason)
			rowsBefore := familyRevocationCount(t)

			// Two writes are told apart by their timestamps, so the second must be later than the first.
			time.Sleep(timestampTick)
			created, err := database.RecordRefreshTokenFamilyRevoked(ctx, nil, family, tc.secondReason)
			require.NoError(t, err, "a family already recorded is not an error")
			assert.False(t, created, "the second call did not write the row, and must not say it did")

			reason, revokedAt, found := familyRevocationRow(t, family)
			require.True(t, found)
			assert.Equal(t, firstReason, reason, "the first reason stays")
			assert.True(t, firstAt.Equal(revokedAt), "the first time stays: first %v, now %v", firstAt, revokedAt)
			assert.Equal(t, rowsBefore, familyRevocationCount(t), "and no second row was written")
			assert.True(t, familyIsRevoked(t, family))
		})
	}
}

func TestRefreshTokenFamilyRevocation_RefusesWhatCannotBeKeyed(t *testing.T) {
	ctx := context.Background()

	t.Run("recording an empty jti is an error and writes nothing", func(t *testing.T) {
		rowsBefore := familyRevocationCount(t)

		created, err := database.RecordRefreshTokenFamilyRevoked(ctx, nil, "", familyRevocationReason)

		require.Error(t, err, "an empty jti on a revocation path is a caller bug, and absorbing it would record the wrong family")
		assert.False(t, created)
		assert.Equal(t, rowsBefore, familyRevocationCount(t))
	})

	t.Run("recording with an empty reason is an error and writes nothing", func(t *testing.T) {
		family := newFamilyJti()
		rowsBefore := familyRevocationCount(t)

		created, err := database.RecordRefreshTokenFamilyRevoked(ctx, nil, family, "")

		require.Error(t, err, "a record that says nothing about why is refused")
		assert.False(t, created)
		assert.Equal(t, rowsBefore, familyRevocationCount(t))
		assert.False(t, familyIsRevoked(t, family), "and the family is not left half recorded")
	})

	t.Run("asking about an empty jti is an error and not a family that is not revoked", func(t *testing.T) {
		revoked, err := database.IsRefreshTokenFamilyRevoked(ctx, nil, "")

		require.Error(t, err, "an error refuses the token and false lets it through, so the two must not be confused")
		assert.False(t, revoked)
	})
}

// The lookup compares the jti as exactly what it is. The column is pinned case-sensitive, and SQL
// Server additionally pads for `=` under every collation, so a jti with a trailing space would
// find the record of the one without; the data layer compares the row it got back against the jti
// it was asked for. The control is the exact jti, read in the same case, so each variation below is
// the only thing that differs from a read that finds the record.
func TestRefreshTokenFamilyRevocation_TheLookupComparesTheJtiExactly(t *testing.T) {
	family := newFamilyJti()
	recordFamily(t, family)
	require.True(t, familyIsRevoked(t, family), "control: the exact jti finds the record")

	for name, asked := range map[string]string{
		"upper case":     strings.ToUpper(family),
		"trailing space": family + " ",
		"leading space":  " " + family,
	} {
		t.Run(name, func(t *testing.T) {
			require.NotEqual(t, family, asked)

			revoked, err := database.IsRefreshTokenFamilyRevoked(context.Background(), nil, asked)

			require.NoError(t, err, "a different spelling is a family that is not recorded, not a fault")
			assert.False(t, revoked, "and it must not read as the recorded one")
		})
	}
}

// The Go comparison above is only reachable on an engine whose `=` folds: SQLite, MySQL and
// PostgreSQL compare the pinned column exactly, so there the row that comes back always equals the
// jti that was asked for and the trailing space case passes without the comparison doing anything.
// SQL Server is the engine that folds in production. So that the comparison is also held where the
// tier runs most often, this gives SQLite a table whose key folds case, which is the same
// symptom, an engine that answers a match for a different spelling, and asks the method through it.
// Only SQLite can do this here: its column declaration is the one thing a test can swap without a
// migration. The other engines are held by the case above, which is the real thing.
func TestRefreshTokenFamilyRevocation_TheLookupDoesNotTrustAnEngineThatFolds(t *testing.T) {
	if dbType() != data.SQLite {
		t.Skipf("%s is held by the trailing space case above; only SQLite's column declaration can be swapped without a migration", dbType())
	}
	ctx := context.Background()
	h := newIsolatedDB(t)
	require.NoError(t, h.Migrator.Migrate(ctx, 54), "migrate to 54")

	// The same table 000054 creates, with one difference: the key's collation.
	_, err := h.SQL.ExecContext(ctx, "DROP TABLE refresh_token_family_revocations")
	require.NoError(t, err)
	_, err = h.SQL.ExecContext(ctx, `CREATE TABLE refresh_token_family_revocations (
		first_refresh_token_jti TEXT NOT NULL COLLATE NOCASE PRIMARY KEY,
		reason TEXT NOT NULL,
		revoked_at DATETIME NOT NULL)`)
	require.NoError(t, err)

	family := newFamilyJti()
	created, err := h.DB.RecordRefreshTokenFamilyRevoked(ctx, nil, family, familyRevocationReason)
	require.NoError(t, err)
	require.True(t, created)
	revoked, err := h.DB.IsRefreshTokenFamilyRevoked(ctx, nil, family)
	require.NoError(t, err)
	require.True(t, revoked, "control: the exact jti finds the record")

	// The premise: this engine's `=` does match the other spelling, so the row is returned for it.
	upper := strings.ToUpper(family)
	require.NotEqual(t, family, upper)
	var matched int
	require.NoError(t, h.SQL.QueryRowContext(ctx, fmt.Sprintf(
		"SELECT COUNT(*) FROM refresh_token_family_revocations WHERE first_refresh_token_jti = '%s'", upper)).Scan(&matched))
	require.Equal(t, 1, matched, "the premise: the engine folds, and returns the row for the other spelling")

	revoked, err = h.DB.IsRefreshTokenFamilyRevoked(ctx, nil, upper)
	require.NoError(t, err)
	assert.False(t, revoked, "the row that came back is another spelling than the one asked for, so it is not that family's record")
}

// The methods run on the transaction they are handed. A record written inside a transaction that
// rolls back leaves the table as it was, which is what makes the revocation's transaction mean
// something: a family recorded by a revocation that did not commit was not revoked.
//
// Everything inside a body goes through the transaction it was handed: SQLite has one connection, so
// a read through the pool from inside the body would wait for the connection the body holds.
func TestRefreshTokenFamilyRevocation_MethodsEnlistInTheCallersTransaction(t *testing.T) {
	ctx := context.Background()

	t.Run("a record in a transaction that rolls back leaves no row", func(t *testing.T) {
		family := newFamilyJti()
		refused := errors.New("the revocation decided against it")

		err := database.RunInTransaction(ctx, func(tx *sql.Tx) error {
			created, recordErr := database.RecordRefreshTokenFamilyRevoked(ctx, tx, family, familyRevocationReason)
			require.NoError(t, recordErr)
			require.True(t, created, "the record is written inside the transaction")
			return refused
		})

		require.ErrorIs(t, err, refused, "the body's error is what comes back")
		_, _, found := familyRevocationRow(t, family)
		assert.False(t, found, "the rolled back record left no row")
		assert.False(t, familyIsRevoked(t, family))

		created, err := database.RecordRefreshTokenFamilyRevoked(ctx, nil, family, familyRevocationReason)
		require.NoError(t, err)
		assert.True(t, created, "and the family is still unrecorded, so the next writer is the creator")
	})

	t.Run("a record in a transaction that commits leaves the row", func(t *testing.T) {
		family := newFamilyJti()

		err := database.RunInTransaction(ctx, func(tx *sql.Tx) error {
			created, recordErr := database.RecordRefreshTokenFamilyRevoked(ctx, tx, family, familyRevocationReason)
			if recordErr != nil {
				return recordErr
			}
			require.True(t, created)
			return nil
		})

		require.NoError(t, err)
		_, _, found := familyRevocationRow(t, family)
		assert.True(t, found, "the committed record is in the table")
		assert.True(t, familyIsRevoked(t, family))
	})

	t.Run("a read on the transaction sees the row the same transaction just wrote", func(t *testing.T) {
		family := newFamilyJti()

		err := database.RunInTransaction(ctx, func(tx *sql.Tx) error {
			before, readErr := database.IsRefreshTokenFamilyRevoked(ctx, tx, family)
			require.NoError(t, readErr)
			require.False(t, before, "control: the family is not recorded until the write below")

			created, recordErr := database.RecordRefreshTokenFamilyRevoked(ctx, tx, family, familyRevocationReason)
			require.NoError(t, recordErr)
			require.True(t, created)

			after, readErr := database.IsRefreshTokenFamilyRevoked(ctx, tx, family)
			require.NoError(t, readErr)
			assert.True(t, after, "the rotation's own transaction reads the record its revocation wrote")

			again, recordErr := database.RecordRefreshTokenFamilyRevoked(ctx, tx, family, "another_reason")
			require.NoError(t, recordErr)
			assert.False(t, again, "and a second record in the same transaction finds the first and writes nothing")
			return nil
		})

		require.NoError(t, err)
		reason, _, found := familyRevocationRow(t, family)
		require.True(t, found)
		assert.Equal(t, familyRevocationReason, reason, "the first reason is the one that was committed")
	})

	t.Run("a sweep in a transaction that rolls back leaves the record", func(t *testing.T) {
		family := newFamilyJti()
		recordFamily(t, family) // no member: the next sweep removes it
		refused := errors.New("the sweep decided against it")

		err := database.RunInTransaction(ctx, func(tx *sql.Tx) error {
			require.NoError(t, database.DeleteOrphanedRefreshTokenFamilyRevocations(ctx, tx))
			return refused
		})

		require.ErrorIs(t, err, refused)
		assert.True(t, familyIsRevoked(t, family), "a sweep that did not commit removed nothing")
	})

	t.Run("a sweep in a transaction that commits removes the record", func(t *testing.T) {
		family := newFamilyJti()
		recordFamily(t, family)

		err := database.RunInTransaction(ctx, func(tx *sql.Tx) error {
			return database.DeleteOrphanedRefreshTokenFamilyRevocations(ctx, tx)
		})

		require.NoError(t, err)
		assert.False(t, familyIsRevoked(t, family), "the committed sweep removed the orphaned record")
	})
}

// seedFamilyMembers writes one refresh token per entry of revoked, all in the family, in the ROPC
// shape (user and client on the row, no code). Each reports whether it is revoked.
func seedFamilyMembers(t *testing.T, family string, revoked ...bool) []*record.RefreshToken {
	t.Helper()
	client := createTestClient(t)
	user := createTestUser(t)

	members := make([]*record.RefreshToken, 0, len(revoked))
	for _, isRevoked := range revoked {
		members = append(members, seedFamilyToken(t, familyTokenSpec{
			FamilyJti: family, UserId: user.Id, ClientId: client.Id, Revoked: isRevoked,
		}))
	}
	return members
}

// The sweep removes the record of a family with no refresh token left, because a token needs a
// parent row to be rotated from and the last member is gone. A member of any kind keeps the record,
// live or revoked, so the sweep can never remove the record of a family a rotation in flight still
// holds the parent of. Each case below varies the membership of one family and nothing else.
func TestRefreshTokenFamilyRevocation_TheOrphanSweep(t *testing.T) {
	ctx := context.Background()
	sweep := func(t *testing.T) {
		t.Helper()
		require.NoError(t, database.DeleteOrphanedRefreshTokenFamilyRevocations(ctx, nil))
	}

	t.Run("a recorded family with a live member keeps its record", func(t *testing.T) {
		family := newFamilyJti()
		seedFamilyMembers(t, family, false)
		recordFamily(t, family)

		sweep(t)

		assert.True(t, familyIsRevoked(t, family))
	})

	t.Run("a recorded family with only revoked members keeps its record", func(t *testing.T) {
		family := newFamilyJti()
		seedFamilyMembers(t, family, true, true)
		recordFamily(t, family)

		sweep(t)

		assert.True(t, familyIsRevoked(t, family), "a revoked member is still a row a rotation could be holding")
	})

	t.Run("a recorded family with no member at all loses its record", func(t *testing.T) {
		family := newFamilyJti()
		recordFamily(t, family)

		sweep(t)

		assert.False(t, familyIsRevoked(t, family))
		_, _, found := familyRevocationRow(t, family)
		assert.False(t, found, "the row is gone, not just unreadable")
	})

	t.Run("a member of another family does not keep the record", func(t *testing.T) {
		family := newFamilyJti()
		seedFamilyMembers(t, newFamilyJti(), false)
		recordFamily(t, family)

		sweep(t)

		assert.False(t, familyIsRevoked(t, family), "the record belongs to its own family's members")
	})

	t.Run("a member whose family jti differs only by case does not keep the record", func(t *testing.T) {
		family := newFamilyJti()
		seedFamilyMembers(t, strings.ToUpper(family), false)
		recordFamily(t, family)

		sweep(t)

		assert.False(t, familyIsRevoked(t, family),
			"both columns are pinned case-sensitive, so the member of another spelling is another family's")
	})

	t.Run("the three cases together, and a second sweep is a no-op", func(t *testing.T) {
		withLive := newFamilyJti()
		withRevoked := newFamilyJti()
		withNone := newFamilyJti()
		liveMembers := seedFamilyMembers(t, withLive, false)
		revokedMembers := seedFamilyMembers(t, withRevoked, true)
		for _, family := range []string{withLive, withRevoked, withNone} {
			recordFamily(t, family)
		}

		sweep(t)

		assert.True(t, familyIsRevoked(t, withLive), "live member: kept")
		assert.True(t, familyIsRevoked(t, withRevoked), "only revoked members: kept")
		assert.False(t, familyIsRevoked(t, withNone), "no member: swept")

		// The sweep reaps records and nothing else: the members are the same rows, in the same state.
		assert.False(t, refreshTokenIsRevoked(t, liveMembers[0].Id), "a live member stays live")
		assert.True(t, refreshTokenIsRevoked(t, revokedMembers[0].Id), "a revoked member stays revoked")

		rowsAfterFirst := familyRevocationCount(t)
		sweep(t)
		assert.Equal(t, rowsAfterFirst, familyRevocationCount(t), "a second sweep finds nothing more to remove")
		assert.True(t, familyIsRevoked(t, withLive))
		assert.True(t, familyIsRevoked(t, withRevoked))
		assert.False(t, familyIsRevoked(t, withNone))
	})
}

// recordOutcome is what one caller of a concurrent first write saw.
type recordOutcome struct {
	created bool
	err     error
}

// concurrentRounds is how many fresh families each concurrent case races over. One round on an
// engine with real row locks may or may not overlap; ten give the interleaving ten chances, and
// every round must satisfy the same contract whichever way it fell.
const concurrentRounds = 10

// recordConcurrently runs two callers that each record the same family in a transaction of their
// own, opened through run, and released together by one closed channel rather than by a pause. Each
// caller reports what its attempt that finished last produced, and only a run that returned nil
// counts as having created the row: a body that wrote and then failed to commit created nothing.
// The wait is bounded by ctx, so a hang ends as a failure and never as a stuck tier.
func recordConcurrently(ctx context.Context, t *testing.T, family string,
	run func(ctx context.Context, fn func(tx *sql.Tx) error) error) []recordOutcome {

	t.Helper()
	const callers = 2

	release := make(chan struct{})
	results := make(chan recordOutcome, callers)
	for caller := 0; caller < callers; caller++ {
		go func() {
			<-release
			var created bool
			err := run(ctx, func(tx *sql.Tx) error {
				var recordErr error
				created, recordErr = database.RecordRefreshTokenFamilyRevoked(ctx, tx, family, familyRevocationReason)
				return recordErr
			})
			results <- recordOutcome{created: err == nil && created, err: err}
		}()
	}
	close(release)

	outcomes := make([]recordOutcome, 0, callers)
	for len(outcomes) < callers {
		select {
		case outcome := <-results:
			outcomes = append(outcomes, outcome)
		case <-ctx.Done():
			require.FailNowf(t, "a concurrent record did not finish",
				"%d of %d callers finished before the deadline: %v", len(outcomes), callers, ctx.Err())
		}
	}
	return outcomes
}

func countCreators(outcomes []recordOutcome) int {
	creators := 0
	for _, outcome := range outcomes {
		if outcome.created {
			creators++
		}
	}
	return creators
}

// Two first writes of one family that overlap: both may read absent, and the second insert then
// loses on the primary key. The contract is that exactly one caller created the row, that the
// other either found it and reported false or lost the key and said so as ErrUniqueViolation, which
// is what a caller reruns on, and that the family reads as revoked afterwards. SQLite has one
// connection, so there the two serialise and the second always finds the row; the other three
// engines are where the loss on the key can happen.
func TestRefreshTokenFamilyRevocation_TwoConcurrentFirstWritesHaveExactlyOneCreator(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	lostTheKey := 0
	for round := 0; round < concurrentRounds; round++ {
		family := newFamilyJti()

		outcomes := recordConcurrently(ctx, t, family, database.RunInTransaction)

		require.Equalf(t, 1, countCreators(outcomes), "round %d: exactly one caller wrote the row; outcomes %+v", round, outcomes)
		for _, outcome := range outcomes {
			switch {
			case outcome.created:
			case outcome.err == nil:
				// It read the winner's row and reported false.
			case errors.Is(outcome.err, data.ErrUniqueViolation):
				lostTheKey++
			default:
				require.Failf(t, "the loser failed for a reason other than the key",
					"round %d: %v", round, outcome.err)
			}
		}
		assert.Truef(t, familyIsRevoked(t, family), "round %d: the family reads as revoked", round)
		_, _, found := familyRevocationRow(t, family)
		assert.Truef(t, found, "round %d: there is a row", round)
	}
	t.Logf("%s: %d of %d rounds ended with a caller losing on the key", dbType(), lostTheKey, concurrentRounds)
}

// The same race through data.RunInTransactionRetryingConflict, which reruns the body once when the
// first attempt lost the key. The rerun reads the row the winner committed and finds it, so both
// callers end without an error, and still exactly one of them created the row.
func TestRefreshTokenFamilyRevocation_TwoConcurrentFirstWritesThroughTheRetryBothSucceed(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	retrying := func(ctx context.Context, fn func(tx *sql.Tx) error) error {
		return data.RunInTransactionRetryingConflict(ctx, database, fn)
	}

	for round := 0; round < concurrentRounds; round++ {
		family := newFamilyJti()

		outcomes := recordConcurrently(ctx, t, family, retrying)

		for _, outcome := range outcomes {
			require.NoErrorf(t, outcome.err, "round %d: a loser on the key is rerun, and the rerun finds the row", round)
		}
		assert.Equalf(t, 1, countCreators(outcomes), "round %d: exactly one caller created the row; outcomes %+v", round, outcomes)
		assert.Truef(t, familyIsRevoked(t, family), "round %d: the family reads as revoked", round)
		reason, _, found := familyRevocationRow(t, family)
		require.Truef(t, found, "round %d: there is a row", round)
		assert.Equalf(t, familyRevocationReason, reason, "round %d: the row is the creator's", round)
	}
}
