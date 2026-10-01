package datatests

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/leodip/goiabada/authserver/internal/authorizerequest"
	"github.com/leodip/goiabada/authserver/internal/data"
	"github.com/leodip/goiabada/authserver/internal/models"
	"github.com/leodip/goiabada/authserver/internal/testutil/fake"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Seam 5 of #437 (#246): the parked authorization request's four methods, against the real
// engines.
//
// The reason this tier owns them. The read carries an `expires_at > now` term that decides, in the
// engine, whether a request is still consumable. The claim is the one-winner arbiter that makes a
// handle single use, and its bool means "THIS statement deleted the row", which four engines that
// disagree about what RowsAffected counts can only answer for themselves. The request form is an
// unbounded text column, which a mock cannot show holds what a request can carry. And whether two
// consumers that both read the row can both act on it is a claim about the engine's row locks.
//
// Run per dialect via: ./run-tests.sh --type data --db <sqlite|mysql|postgres|mssql>

// newAuthorizeRequest builds an unsaved parked request with a fresh handle. `now` fixes the
// deadline so nothing here depends on the wall clock.
func newAuthorizeRequest(now time.Time, ttl time.Duration) *models.AuthorizeRequest {
	handle := fake.UUID() + fake.UUID()
	return &models.AuthorizeRequest{
		Handle:      handle,
		HandleHash:  sha256Hex(handle),
		RequestForm: url.Values{"client_id": {"client-" + fake.UUID()}, "state": {"s"}}.Encode(),
		ExpiresAt:   now.Add(ttl),
	}
}

func createTestAuthorizeRequest(t *testing.T, now time.Time, ttl time.Duration) *models.AuthorizeRequest {
	t.Helper()
	ar := newAuthorizeRequest(now, ttl)
	require.NoError(t, database.CreateAuthorizeRequest(context.Background(), nil, ar), "CreateAuthorizeRequest")
	require.NotZero(t, ar.Id, "CreateAuthorizeRequest must report the id it inserted")
	return ar
}

// authorizeRequestExists reads the row's presence straight from the table, so an assertion about
// a claim or a sweep does not go through the read whose predicate is also under test.
func authorizeRequestExists(t *testing.T, id int64) bool {
	t.Helper()
	var n int
	// The id is inlined rather than bound, so this one query needs no per-engine placeholder
	// syntax. It is an int64 the insert returned, not caller input.
	require.NoError(t, rawSQLHandle(t).QueryRow(
		fmt.Sprintf("SELECT COUNT(*) FROM authorize_requests WHERE id = %d", id)).Scan(&n))
	return n > 0
}

// The form round-trips whole at a size a bounded column would refuse. The merged query and body
// can exceed MySQL's TEXT ceiling of 65,535 bytes while every parameter respects the bounds
// /auth/authorize applies (65,955 bytes was measured through the real body limit), so the column is
// LONGTEXT there, TEXT on PostgreSQL and SQLite, NVARCHAR(MAX) on SQL Server. A bound on it would
// refuse a request the endpoint accepts.
func TestAuthorizeRequest_CreateAndLoad(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Microsecond)

	ar := newAuthorizeRequest(now, authorizerequest.Lifetime)
	// Past the TEXT ceiling on every engine that has one, and multi-byte, so a column that is wide
	// in characters but narrow in bytes, or a connection charset that mangles, would show.
	ar.RequestForm = url.Values{
		"client_id":     {"c"},
		"id_token_hint": {strings.Repeat("aé€😀", 20000)},
		"state":         {"one", "two"},
	}.Encode()
	require.Greater(t, len(ar.RequestForm), 65535, "the fixture must exceed MySQL's TEXT ceiling")

	require.NoError(t, database.CreateAuthorizeRequest(context.Background(), nil, ar), "CreateAuthorizeRequest")
	require.NotZero(t, ar.Id)

	loaded, err := database.GetAuthorizeRequestByHandleHash(context.Background(), nil, ar.HandleHash, now)
	require.NoError(t, err, "GetAuthorizeRequestByHandleHash")
	require.NotNil(t, loaded, "a live request must be found")

	assert.Equal(t, ar.Id, loaded.Id)
	assert.Equal(t, ar.HandleHash, loaded.HandleHash)
	assert.Equal(t, ar.RequestForm, loaded.RequestForm, "the form must round-trip whole, past 64 KiB")
	assert.WithinDuration(t, ar.ExpiresAt, loaded.ExpiresAt, time.Second)
	assert.True(t, loaded.CreatedAt.Valid, "created_at is stamped by the insert")
	assert.True(t, loaded.UpdatedAt.Valid, "updated_at is stamped by the insert")

	// A hash no row carries is nil and no error: "there is no such request" and "I could not ask"
	// are different answers, and only the first is a refusal the browser can act on.
	missing, err := database.GetAuthorizeRequestByHandleHash(context.Background(), nil, sha256Hex("nobody"), now)
	require.NoError(t, err, "an absent request is not an error")
	assert.Nil(t, missing)
}

// The column holds the digest and never the handle: the model tags Handle `db:"-"`, so the
// plaintext has a field a caller can carry it in and no column it can reach. Read column by column
// rather than through the model, because the claim is about the row.
func TestAuthorizeRequest_ColumnHoldsTheHashAndNeverTheHandle(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Microsecond)
	ar := createTestAuthorizeRequest(t, now, time.Hour)
	require.NotEmpty(t, ar.Handle, "the test must have set a plaintext handle to look for")

	var hash, form string
	require.NoError(t, rawSQLHandle(t).QueryRow(
		fmt.Sprintf("SELECT handle_hash, request_form FROM authorize_requests WHERE id = %d", ar.Id)).Scan(&hash, &form))

	assert.Equal(t, sha256Hex(ar.Handle), hash, "the column holds the digest of the handle")
	assert.NotContains(t, hash, ar.Handle)
	assert.NotContains(t, form, ar.Handle)

	loaded, err := database.GetAuthorizeRequestByHandleHash(context.Background(), nil, ar.HandleHash, now)
	require.NoError(t, err)
	require.NotNil(t, loaded)
	assert.Empty(t, loaded.Handle, "a loaded request has no plaintext handle to give")
}

// expires_at > now is decided in the engine, so an expired request reads as absent whether or not
// the sweep has reached it. The boundary is strict: a request whose deadline is `now` is expired.
func TestAuthorizeRequest_ExpiryIsDecidedByTheRead(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Microsecond)
	ar := createTestAuthorizeRequest(t, now, time.Minute)

	cases := []struct {
		name  string
		at    time.Time
		found bool
	}{
		{"a microsecond before the deadline", ar.ExpiresAt.Add(-time.Microsecond), true},
		{"exactly at the deadline", ar.ExpiresAt, false},
		{"a microsecond after the deadline", ar.ExpiresAt.Add(time.Microsecond), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			loaded, err := database.GetAuthorizeRequestByHandleHash(context.Background(), nil, ar.HandleHash, tc.at)
			require.NoError(t, err)
			if tc.found {
				require.NotNil(t, loaded)
				assert.Equal(t, ar.Id, loaded.Id)
			} else {
				assert.Nil(t, loaded, "an expired request must read as absent")
			}
		})
	}
	assert.True(t, authorizeRequestExists(t, ar.Id), "the row is still there: expiry is the read's rule, the sweep's job is disk")
}

// A handle's digest is compared as exactly what it is. The columns are pinned case-sensitive, and
// SQL Server additionally pads for `=` under every collation, so a hash with trailing spaces would
// find the row of the one without; the data layer compares the row it got back against the hash it
// was asked for.
func TestAuthorizeRequest_TheLookupComparesTheHashExactly(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Microsecond)
	ar := createTestAuthorizeRequest(t, now, time.Hour)

	for name, hash := range map[string]string{
		"upper case":     strings.ToUpper(ar.HandleHash),
		"trailing space": ar.HandleHash + " ",
		"leading space":  " " + ar.HandleHash,
	} {
		t.Run(name, func(t *testing.T) {
			require.NotEqual(t, ar.HandleHash, hash)
			loaded, err := database.GetAuthorizeRequestByHandleHash(context.Background(), nil, hash, now)
			require.NoError(t, err)
			assert.Nil(t, loaded, "a different spelling of the hash must not find the row")
		})
	}
}

func TestAuthorizeRequest_RefusesWhatCannotBeKeyed(t *testing.T) {
	now := time.Now().UTC()

	err := database.CreateAuthorizeRequest(context.Background(), nil, &models.AuthorizeRequest{RequestForm: "a=b", ExpiresAt: now.Add(time.Hour)})
	assert.Error(t, err, "an empty handle hash names no row")

	err = database.CreateAuthorizeRequest(context.Background(), nil, &models.AuthorizeRequest{HandleHash: sha256Hex("x"), RequestForm: "a=b"})
	assert.Error(t, err, "a request that never expires is a row nothing would ever sweep")

	_, err = database.GetAuthorizeRequestByHandleHash(context.Background(), nil, "", now)
	assert.Error(t, err, "an empty hash is a caller bug, not a filter that matches every row")

	_, err = database.ClaimAuthorizeRequest(context.Background(), nil, 0)
	assert.Error(t, err)
}

func TestAuthorizeRequest_TheHandleHashIsUnique(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Microsecond)
	first := createTestAuthorizeRequest(t, now, time.Hour)

	duplicate := newAuthorizeRequest(now, time.Hour)
	duplicate.HandleHash = first.HandleHash
	err := database.CreateAuthorizeRequest(context.Background(), nil, duplicate)

	require.Error(t, err, "two rows for one handle would let one link run two ceremonies")
	assert.True(t, errors.Is(err, data.ErrUniqueViolation), "and the engine's refusal must reach the caller classified: %v", err)
	assert.Zero(t, duplicate.Id, "a refused insert reports no id")
	assert.False(t, duplicate.CreatedAt.Valid, "and leaves the model as it found it")
}

// The claim is the one-winner arbiter: only the call that deleted the row is told so, on every
// engine, whatever the engine's RowsAffected counts elsewhere. Run in sequence this is what the
// second of two consumers sees on any engine, and it is the whole of the arbiter on SQLite, whose
// single connection cannot overlap them.
func TestAuthorizeRequest_OnlyTheFirstClaimWins(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Microsecond)
	ar := createTestAuthorizeRequest(t, now, time.Hour)

	first, err := database.ClaimAuthorizeRequest(context.Background(), nil, ar.Id)
	require.NoError(t, err)
	assert.True(t, first, "the first claim deletes the row")
	assert.False(t, authorizeRequestExists(t, ar.Id))

	second, err := database.ClaimAuthorizeRequest(context.Background(), nil, ar.Id)
	require.NoError(t, err, "a claim of a row that is gone is not an error")
	assert.False(t, second, "and it must not report a win: this is what keeps a link from running twice")

	gone, err := database.GetAuthorizeRequestByHandleHash(context.Background(), nil, ar.HandleHash, now)
	require.NoError(t, err)
	assert.Nil(t, gone)

	unknown, err := database.ClaimAuthorizeRequest(context.Background(), nil, ar.Id+1_000_000)
	require.NoError(t, err)
	assert.False(t, unknown)
}

func TestAuthorizeRequest_AClaimOnlyTouchesItsOwnRow(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Microsecond)
	mine := createTestAuthorizeRequest(t, now, time.Hour)
	theirs := createTestAuthorizeRequest(t, now, time.Hour)

	won, err := database.ClaimAuthorizeRequest(context.Background(), nil, mine.Id)
	require.NoError(t, err)
	require.True(t, won)

	assert.True(t, authorizeRequestExists(t, theirs.Id), "another request's row must survive the claim")
	stillThere, err := database.GetAuthorizeRequestByHandleHash(context.Background(), nil, theirs.HandleHash, now)
	require.NoError(t, err)
	assert.NotNil(t, stillThere)
}

// The sweep reaps on expires_at alone and only what is expired. It is what stops the table
// growing, so the boundary and the survivors are asserted, not just that something went.
func TestAuthorizeRequest_TheSweepRemovesExpiredRowsAndNothingElse(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Microsecond)
	expired := createTestAuthorizeRequest(t, now, -time.Minute)
	atTheBoundary := createTestAuthorizeRequest(t, now, 0)
	live := createTestAuthorizeRequest(t, now, time.Hour)

	require.NoError(t, database.DeleteExpiredAuthorizeRequests(context.Background(), nil, now))

	assert.False(t, authorizeRequestExists(t, expired.Id), "an expired row is swept")
	assert.True(t, authorizeRequestExists(t, atTheBoundary.Id),
		"a row whose deadline is the sweep's cutoff is kept: the read already refuses it, and the next sweep has it")
	assert.True(t, authorizeRequestExists(t, live.Id), "a live row is never swept")

	require.NoError(t, database.DeleteExpiredAuthorizeRequests(context.Background(), nil, now.Add(time.Microsecond)))
	assert.False(t, authorizeRequestExists(t, atTheBoundary.Id))
	assert.True(t, authorizeRequestExists(t, live.Id))

	// Sweeping nothing is not an error.
	require.NoError(t, database.DeleteExpiredAuthorizeRequests(context.Background(), nil, now))
}

// The methods run on the transaction they are handed. A request parked and a request claimed
// inside a transaction that rolls back leave the table as it was, which is what makes the
// consuming pair's transaction mean something: a claim that did not commit was not a claim.
func TestAuthorizeRequest_MethodsEnlistInTheCallersTransaction(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Microsecond)

	t.Run("a rolled back create leaves no row", func(t *testing.T) {
		tx, err := database.BeginTransaction(context.Background())
		require.NoError(t, err)
		// A failing assertion must not leave the transaction open: SQLite has one connection, and
		// every later test in the tier would wait for it.
		defer func() { _ = database.RollbackTransaction(context.Background(), tx) }()
		ar := newAuthorizeRequest(now, time.Hour)
		require.NoError(t, database.CreateAuthorizeRequest(context.Background(), tx, ar))
		require.NoError(t, database.RollbackTransaction(context.Background(), tx))

		assert.False(t, authorizeRequestExists(t, ar.Id))
		loaded, err := database.GetAuthorizeRequestByHandleHash(context.Background(), nil, ar.HandleHash, now)
		require.NoError(t, err)
		assert.Nil(t, loaded)
	})

	t.Run("a rolled back claim leaves the request consumable", func(t *testing.T) {
		ar := createTestAuthorizeRequest(t, now, time.Hour)

		tx, err := database.BeginTransaction(context.Background())
		require.NoError(t, err)
		defer func() { _ = database.RollbackTransaction(context.Background(), tx) }()
		won, err := database.ClaimAuthorizeRequest(context.Background(), tx, ar.Id)
		require.NoError(t, err)
		require.True(t, won)
		require.NoError(t, database.RollbackTransaction(context.Background(), tx))

		assert.True(t, authorizeRequestExists(t, ar.Id))
		again, err := database.ClaimAuthorizeRequest(context.Background(), nil, ar.Id)
		require.NoError(t, err)
		assert.True(t, again, "the rolled back claim never happened, so the next consumer still wins")
	})

	t.Run("a committed claim is gone for good", func(t *testing.T) {
		ar := createTestAuthorizeRequest(t, now, time.Hour)

		tx, err := database.BeginTransaction(context.Background())
		require.NoError(t, err)
		defer func() { _ = database.RollbackTransaction(context.Background(), tx) }()
		won, err := database.ClaimAuthorizeRequest(context.Background(), tx, ar.Id)
		require.NoError(t, err)
		require.True(t, won)
		require.NoError(t, database.CommitTransaction(context.Background(), tx))

		assert.False(t, authorizeRequestExists(t, ar.Id))
	})
}

// Two consumers that BOTH read the row before either claims it: the interleaving the claim exists
// for. The first claim holds the row's lock; the second waits on it, and when the first commits
// the second's DELETE finds no row to remove and is told so. Exactly one winner, one refusal.
//
// Without the claim's own count, a consumer that had read the row would act on it whatever became
// of the row afterwards, and the two GETs of one link would both run the ceremony. Skipped on
// SQLite, whose single connection cannot hold two consumers open at once, so the interleaving can
// never occur there; the sequential case above is the arbiter it exercises.
func TestAuthorizeRequest_TwoOverlappingConsumersHaveExactlyOneWinner(t *testing.T) {
	if dbType() == data.SQLite {
		t.Skip("SQLite has one connection, so two consumers cannot both hold a read open; the sequential case covers it")
	}
	other := secondDatabase(t) // before anything is held: see secondDatabase for why

	now := time.Now().UTC().Truncate(time.Microsecond)
	ar := createTestAuthorizeRequest(t, now, time.Hour)

	first, err := database.BeginTransaction(context.Background())
	require.NoError(t, err, "opening the first consumer's transaction")
	defer func() { _ = database.RollbackTransaction(context.Background(), first) }()
	second, err := other.BeginTransaction(context.Background())
	require.NoError(t, err, "opening the second consumer's transaction")
	defer func() { _ = other.RollbackTransaction(context.Background(), second) }()

	// Both read the row while it is there.
	readByFirst, err := database.GetAuthorizeRequestByHandleHash(context.Background(), first, ar.HandleHash, now)
	require.NoError(t, err)
	require.NotNil(t, readByFirst, "the first consumer reads the request")
	readBySecond, err := other.GetAuthorizeRequestByHandleHash(context.Background(), second, ar.HandleHash, now)
	require.NoError(t, err)
	require.NotNil(t, readBySecond, "the second consumer read it too, before the first claimed it")

	// The first claims and holds the row's lock until it commits.
	won, err := database.ClaimAuthorizeRequest(context.Background(), first, readByFirst.Id)
	require.NoError(t, err)
	require.True(t, won, "the first claim deletes the row")

	type claimOutcome struct {
		won bool
		err error
	}
	waiting := goBlocked(t, "the second consumer's claim", first, func(reached func()) claimOutcome {
		reached()
		claimed, claimErr := other.ClaimAuthorizeRequest(context.Background(), second, readBySecond.Id)
		return claimOutcome{won: claimed, err: claimErr}
	})
	waiting.requireBlocked(t)
	waiting.requireStillWaiting(t)
	require.NoError(t, database.CommitTransaction(context.Background(), first), "committing the winner")

	outcome := waiting.await(t)
	require.NoError(t, outcome.err, "the loser waits for the winner and is told it lost; it is not a deadlock or a fault")
	assert.False(t, outcome.won, "the second claim must find the row gone: one link, one ceremony")

	// The loser ends its transaction as Consume does, by committing: it found nothing to act on and
	// returns nil. The check below reads through the pool, and SQL Server keeps the ghost of the
	// deleted row locked for the transaction that waited on it until that transaction ends.
	require.NoError(t, other.CommitTransaction(context.Background(), second), "committing the loser")
	assert.False(t, authorizeRequestExists(t, ar.Id))
}

// The two operations the handlers call, on the real engines: what Park writes Consume reads back
// byte for byte, once. It is what shows the form encoding, the hash, the expiry predicate and the
// claim agree with each other, which no mock of one of them can.
func TestAuthorizeRequest_ParkThenConsumeOnTheRealDatabase(t *testing.T) {
	ctx := context.Background()
	form := url.Values{
		"client_id": {"c"},
		"state":     {"one", "a & b = c ; d % e + f", "é€😀"},
		"nonce":     {""},
	}

	handle, err := authorizerequest.Park(ctx, database, form)
	require.NoError(t, err)
	require.True(t, authorizerequest.IsWellFormedHandle(handle))

	got, found, err := authorizerequest.Consume(ctx, database, handle)
	require.NoError(t, err)
	require.True(t, found)
	assert.Equal(t, form, got)

	again, found, err := authorizerequest.Consume(ctx, database, handle)
	require.NoError(t, err)
	assert.False(t, found, "a handle is single use")
	assert.Nil(t, again)
}

func TestAuthorizeRequest_ConsumeRefusesAnExpiredAndAnUnknownHandle(t *testing.T) {
	ctx := context.Background()

	// A request that expired a second ago, written straight through the data layer because Park
	// only writes live ones. The row is still in the table: the sweep has not run. Well formed, or
	// Consume would refuse it before reading, and random, so the case can run twice on one database.
	handle := wellFormedHandle()
	require.NoError(t, database.CreateAuthorizeRequest(ctx, nil, &models.AuthorizeRequest{
		HandleHash:  sha256Hex(handle),
		RequestForm: "client_id=c",
		ExpiresAt:   time.Now().UTC().Add(-time.Second),
	}))

	form, found, err := authorizerequest.Consume(ctx, database, handle)
	require.NoError(t, err)
	assert.False(t, found, "an expired request is refused before the sweep reaches it")
	assert.Nil(t, form)

	form, found, err = authorizerequest.Consume(ctx, database, wellFormedHandle())
	require.NoError(t, err)
	assert.False(t, found, "an unknown handle is the same refusal")
	assert.Nil(t, form)
}

// wellFormedHandle is a handle authorizerequest accepts that nothing has parked: 42 letters and
// a last character whose two spare bits are zero.
func wellFormedHandle() string {
	return fake.LetterN(42) + "A"
}

// A merged form past MySQL's TEXT ceiling takes the whole trip: parked, stored, read and parsed.
func TestAuthorizeRequest_AFormPast64KiBTakesTheWholeTrip(t *testing.T) {
	ctx := context.Background()
	form := url.Values{
		"client_id":     {"c"},
		"id_token_hint": {strings.Repeat("h", 40000)},
		"acr_values":    {strings.Repeat("a", 30000)},
	}
	require.Greater(t, len(form.Encode()), 65535)

	handle, err := authorizerequest.Park(ctx, database, form)
	require.NoError(t, err)

	got, found, err := authorizerequest.Consume(ctx, database, handle)
	require.NoError(t, err)
	require.True(t, found)
	assert.Equal(t, form, got)
}
