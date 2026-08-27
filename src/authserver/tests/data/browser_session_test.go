package datatests

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/leodip/goiabada/core/data/mssqldb"
	"github.com/leodip/goiabada/core/data/mysqldb"
	"github.com/leodip/goiabada/core/data/postgresdb"
	"github.com/leodip/goiabada/core/data/sqlitedb"
	"github.com/leodip/goiabada/core/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Seam 2 of #266: the six browser session methods, against the real engines.
//
// The reason this tier owns them. Three of the six carry an `expires_at > now` term that
// decides, in the engine, whether a session is still alive, and one of them is a
// conditional update whose bool means "a row transitioned" rather than "a row matched".
// Neither property survives a mock: a mock returns what it was told to return, and the
// four engines disagree about what RowsAffected counts. The isolation the owner column
// provides is the same kind of claim, and so is the unique index that backs it.
//
// Run per dialect via: ./run-tests.sh --type data --db <sqlite|mysql|postgres|mssql>

// The two owner values. They are literals here rather than constants because the store
// that names them is the next stage's; what this tier cares about is only that two
// distinct values keep two populations apart.
const (
	ownerAuthServer   = "authserver"
	ownerAdminConsole = "adminconsole"
)

// sha256Hex is what the store puts in session_id_hash, and what these tests compute
// independently rather than reading back from the code under test.
func sha256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// rawSQLHandle reaches the *sql.DB behind the dialect database, so a test can read a row
// column by column rather than through the model. Only one case needs it: the one
// asserting the plaintext identifier reaches no column at all, which is a claim about
// the columns and not about the struct that maps them.
func rawSQLHandle(t *testing.T) *sql.DB {
	t.Helper()
	switch d := database.(type) {
	case *sqlitedb.SQLiteDatabase:
		return d.DB
	case *mysqldb.MySQLDatabase:
		return d.DB
	case *postgresdb.PostgresDatabase:
		return d.DB
	case *mssqldb.MsSQLDatabase:
		return d.DB
	}
	t.Fatalf("no raw handle for database type %T", database)
	return nil
}

// newBrowserSession builds an unsaved session with a fresh identifier. `now` fixes both
// timestamps so nothing here depends on the wall clock: every case below states its own
// times and the engine compares against the value it was handed.
func newBrowserSession(owner string, now time.Time, ttl time.Duration) *models.BrowserSession {
	id := uuid.New().String() + uuid.New().String()
	return &models.BrowserSession{
		Owner:         owner,
		SessionId:     id,
		SessionIdHash: sha256Hex(id),
		Data:          "ciphertext-" + uuid.New().String(),
		LastAccessed:  now,
		ExpiresAt:     now.Add(ttl),
	}
}

func createTestBrowserSession(t *testing.T, owner string, now time.Time, ttl time.Duration) *models.BrowserSession {
	t.Helper()
	bs := newBrowserSession(owner, now, ttl)
	require.NoError(t, database.CreateBrowserSession(nil, bs), "CreateBrowserSession")
	require.NotZero(t, bs.Id, "CreateBrowserSession must report the id it inserted")
	return bs
}

func TestBrowserSession_CreateAndLoad(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Microsecond)

	bs := newBrowserSession(ownerAuthServer, now, time.Hour)
	// Long enough that a short varchar would refuse it. The admin console's session
	// carries an entire token set, and the whole point of the change is that no size the
	// project cannot promise ends up in a cookie; it has to end up somewhere.
	bs.Data = strings.Repeat("x", 64*1024)

	require.NoError(t, database.CreateBrowserSession(nil, bs), "CreateBrowserSession")
	require.NotZero(t, bs.Id)

	loaded, err := database.GetBrowserSessionByOwnerAndSessionIdHash(nil, bs.Owner, bs.SessionIdHash, now)
	require.NoError(t, err, "GetBrowserSessionByOwnerAndSessionIdHash")
	require.NotNil(t, loaded, "a live session must be found")

	assert.Equal(t, bs.Id, loaded.Id)
	assert.Equal(t, bs.Owner, loaded.Owner)
	assert.Equal(t, bs.SessionIdHash, loaded.SessionIdHash)
	assert.Equal(t, bs.Data, loaded.Data, "the blob must round-trip whole, at 64 KB")
	assert.WithinDuration(t, bs.LastAccessed, loaded.LastAccessed, time.Second)
	assert.WithinDuration(t, bs.ExpiresAt, loaded.ExpiresAt, time.Second)
	assert.True(t, loaded.CreatedAt.Valid, "created_at is stamped by the insert")
	assert.True(t, loaded.UpdatedAt.Valid, "updated_at is stamped by the insert")

	// A hash no row carries is nil and no error: "there is no such session" and "I could
	// not ask" are different answers, and only the first is a fresh session.
	missing, err := database.GetBrowserSessionByOwnerAndSessionIdHash(nil, bs.Owner, sha256Hex("nobody"), now)
	require.NoError(t, err, "an absent session is not an error")
	assert.Nil(t, missing)
}

// TestBrowserSession_ColumnHoldsTheHashAndNeverTheIdentifier pins decision 4. The model
// tags SessionId `db:"-"`, so the plaintext has a field a caller can carry it in and no
// column it can reach. Read column by column rather than through the model, because the
// claim is about the row.
func TestBrowserSession_ColumnHoldsTheHashAndNeverTheIdentifier(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Microsecond)
	bs := createTestBrowserSession(t, ownerAuthServer, now, time.Hour)
	require.NotEmpty(t, bs.SessionId, "the test must have set a plaintext identifier to look for")

	raw := rawSQLHandle(t)
	// The id is inlined rather than bound, so this one query needs no per-engine
	// placeholder syntax. It is an int64 the insert just returned, not caller input.
	row := raw.QueryRow(fmt.Sprintf(
		"SELECT owner, session_id_hash, data FROM browser_sessions WHERE id = %d", bs.Id))

	var owner, hash, data string
	require.NoError(t, row.Scan(&owner, &hash, &data), "read the row back column by column")

	assert.Equal(t, sha256Hex(bs.SessionId), hash, "the column holds the digest of the identifier")
	assert.NotEqual(t, bs.SessionId, hash)
	for name, value := range map[string]string{"owner": owner, "session_id_hash": hash, "data": data} {
		assert.NotContains(t, value, bs.SessionId,
			"the plaintext identifier must appear in no column, and it is in %s", name)
	}

	// And the read path does not carry it back either, so nothing downstream can come to
	// depend on a value that is not stored.
	loaded, err := database.GetBrowserSessionByOwnerAndSessionIdHash(nil, bs.Owner, bs.SessionIdHash, now)
	require.NoError(t, err)
	require.NotNil(t, loaded)
	assert.Empty(t, loaded.SessionId, "a loaded session has no plaintext identifier to give")
}

// TestBrowserSession_TwoOwnersMayHoldTheSameHash is the isolation decision 3 rests on,
// and nothing else in the suite would notice its loss. One table serves both
// applications, so the owner column is the only thing keeping the two populations apart:
// if it dropped out of the predicate, the admin console's endpoint could name an auth
// server session.
func TestBrowserSession_TwoOwnersMayHoldTheSameHash(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Microsecond)

	shared := uuid.New().String() + uuid.New().String()
	hash := sha256Hex(shared)

	authServer := &models.BrowserSession{
		Owner: ownerAuthServer, SessionId: shared, SessionIdHash: hash,
		Data: "auth server contents", LastAccessed: now, ExpiresAt: now.Add(time.Hour),
	}
	adminConsole := &models.BrowserSession{
		Owner: ownerAdminConsole, SessionId: shared, SessionIdHash: hash,
		Data: "admin console contents", LastAccessed: now, ExpiresAt: now.Add(time.Hour),
	}

	require.NoError(t, database.CreateBrowserSession(nil, authServer),
		"the unique index is on (owner, session_id_hash), so one hash under two owners is allowed")
	require.NoError(t, database.CreateBrowserSession(nil, adminConsole))

	loadedAuthServer, err := database.GetBrowserSessionByOwnerAndSessionIdHash(nil, ownerAuthServer, hash, now)
	require.NoError(t, err)
	require.NotNil(t, loadedAuthServer)
	assert.Equal(t, "auth server contents", loadedAuthServer.Data,
		"each owner must load its own row and never the other's")

	loadedAdminConsole, err := database.GetBrowserSessionByOwnerAndSessionIdHash(nil, ownerAdminConsole, hash, now)
	require.NoError(t, err)
	require.NotNil(t, loadedAdminConsole)
	assert.Equal(t, "admin console contents", loadedAdminConsole.Data)

	// And a write under one owner does not reach the other's row.
	moved, err := database.UpdateBrowserSessionData(nil, ownerAdminConsole, hash, "rewritten", now, now.Add(2*time.Hour))
	require.NoError(t, err)
	assert.True(t, moved)

	loadedAuthServer, err = database.GetBrowserSessionByOwnerAndSessionIdHash(nil, ownerAuthServer, hash, now)
	require.NoError(t, err)
	require.NotNil(t, loadedAuthServer)
	assert.Equal(t, "auth server contents", loadedAuthServer.Data,
		"a write scoped to one owner must leave the other owner's row alone")

	// A delete is scoped the same way.
	require.NoError(t, database.DeleteBrowserSession(nil, ownerAdminConsole, hash))

	gone, err := database.GetBrowserSessionByOwnerAndSessionIdHash(nil, ownerAdminConsole, hash, now)
	require.NoError(t, err)
	assert.Nil(t, gone)

	survivor, err := database.GetBrowserSessionByOwnerAndSessionIdHash(nil, ownerAuthServer, hash, now)
	require.NoError(t, err)
	assert.NotNil(t, survivor, "deleting one owner's session must not delete the other's")
}

func TestBrowserSession_UniqueOwnerAndSessionIdHash(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Microsecond)
	existing := createTestBrowserSession(t, ownerAuthServer, now, time.Hour)

	duplicate := &models.BrowserSession{
		Owner: existing.Owner, SessionId: existing.SessionId, SessionIdHash: existing.SessionIdHash,
		Data: "second row", LastAccessed: now, ExpiresAt: now.Add(time.Hour),
	}
	assert.Error(t, database.CreateBrowserSession(nil, duplicate),
		"two sessions of one owner must not share a session_id_hash")
}

// TestBrowserSession_UpdateAndTouchReportTransitions covers what the bool means, and that
// a touch moves expires_at as well as last_accessed. The second half is the load-bearing
// one: the idle window is expressed in expires_at, so a touch that left it alone would
// turn the idle timeout into an absolute one.
func TestBrowserSession_UpdateAndTouchReportTransitions(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Microsecond)
	bs := createTestBrowserSession(t, ownerAuthServer, now, time.Hour)

	moved, err := database.UpdateBrowserSessionData(nil, bs.Owner, bs.SessionIdHash, "new contents",
		now.Add(time.Minute), now.Add(3*time.Hour))
	require.NoError(t, err, "UpdateBrowserSessionData")
	assert.True(t, moved, "a live row transitions")

	loaded, err := database.GetBrowserSessionByOwnerAndSessionIdHash(nil, bs.Owner, bs.SessionIdHash, now)
	require.NoError(t, err)
	require.NotNil(t, loaded)
	assert.Equal(t, "new contents", loaded.Data)
	assert.WithinDuration(t, now.Add(time.Minute), loaded.LastAccessed, time.Second)
	assert.WithinDuration(t, now.Add(3*time.Hour), loaded.ExpiresAt, time.Second)

	touched, err := database.TouchBrowserSession(nil, bs.Owner, bs.SessionIdHash,
		now.Add(2*time.Minute), now.Add(5*time.Hour))
	require.NoError(t, err, "TouchBrowserSession")
	assert.True(t, touched)

	loaded, err = database.GetBrowserSessionByOwnerAndSessionIdHash(nil, bs.Owner, bs.SessionIdHash, now)
	require.NoError(t, err)
	require.NotNil(t, loaded)
	assert.Equal(t, "new contents", loaded.Data, "a touch must not disturb the contents")
	assert.WithinDuration(t, now.Add(2*time.Minute), loaded.LastAccessed, time.Second)
	assert.WithinDuration(t, now.Add(5*time.Hour), loaded.ExpiresAt, time.Second,
		"a touch moves expires_at too, or the idle window could never be extended")

	// A hash no row carries reports false rather than an error: nothing failed, there was
	// simply nothing to write.
	absent := sha256Hex("no such session")

	moved, err = database.UpdateBrowserSessionData(nil, bs.Owner, absent, "x", now, now.Add(time.Hour))
	require.NoError(t, err)
	assert.False(t, moved, "no row transitions for a hash no row carries")

	touched, err = database.TouchBrowserSession(nil, bs.Owner, absent, now, now.Add(time.Hour))
	require.NoError(t, err)
	assert.False(t, touched)
}

// TestBrowserSession_TouchTwiceWithOneClockStillReportsLive pins the one engine
// difference this table's liveness answer turns on.
//
// TouchBrowserSession writes last_accessed, expires_at and updated_at, all three derived
// from the single `now` it is handed, and reports liveness from RowsAffected. SQLite,
// PostgreSQL and SQL Server report rows MATCHED; MySQL reports rows CHANGED, so a
// statement that matched a row and wrote it the values already there answers zero. Two
// concurrent requests from one browser that both find last_accessed stale and both stamp
// the same microsecond produce exactly that, and a false answer costs the browser its
// session: the store reads it as "the row is gone" and hands back a fresh one, signing a
// user out for a reason nobody could see.
//
// Passing this second touch by an identical clock is what says the answer comes from the
// row's existence rather than from whether the write changed anything. Three of the four
// engines pass it whatever the code does, which is why the case says so here rather than
// leaving a green sqlite run to be read as coverage (#266).
func TestBrowserSession_TouchTwiceWithOneClockStillReportsLive(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Microsecond)
	bs := createTestBrowserSession(t, ownerAuthServer, now, time.Hour)

	stamp := now.Add(time.Minute)
	expires := now.Add(2 * time.Hour)

	first, err := database.TouchBrowserSession(nil, bs.Owner, bs.SessionIdHash, stamp, expires)
	require.NoError(t, err, "TouchBrowserSession")
	assert.True(t, first, "a live row transitions")

	// Byte for byte the same write, which is what two requests sharing a microsecond do.
	second, err := database.TouchBrowserSession(nil, bs.Owner, bs.SessionIdHash, stamp, expires)
	require.NoError(t, err, "TouchBrowserSession")
	assert.True(t, second,
		"a row that is plainly there reports live even when the write changed nothing")

	loaded, err := database.GetBrowserSessionByOwnerAndSessionIdHash(nil, bs.Owner, bs.SessionIdHash, now)
	require.NoError(t, err)
	require.NotNil(t, loaded, "and the row is still there to be read")
	assert.WithinDuration(t, stamp, loaded.LastAccessed, time.Second)

	// An expired row still answers false, so confirming existence has not turned the
	// liveness answer into "the hash is known".
	expired := createTestBrowserSession(t, ownerAuthServer, now.Add(-2*time.Hour), time.Hour)
	touched, err := database.TouchBrowserSession(nil, expired.Owner, expired.SessionIdHash, now, now.Add(time.Hour))
	require.NoError(t, err)
	assert.False(t, touched, "an expired row is not live, however the count is read")
}

func TestBrowserSession_DeleteRemovesOnlyTheNamedSession(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Microsecond)
	target := createTestBrowserSession(t, ownerAuthServer, now, time.Hour)
	bystander := createTestBrowserSession(t, ownerAuthServer, now, time.Hour)

	require.NoError(t, database.DeleteBrowserSession(nil, target.Owner, target.SessionIdHash),
		"DeleteBrowserSession")

	gone, err := database.GetBrowserSessionByOwnerAndSessionIdHash(nil, target.Owner, target.SessionIdHash, now)
	require.NoError(t, err)
	assert.Nil(t, gone)

	survivor, err := database.GetBrowserSessionByOwnerAndSessionIdHash(nil, bystander.Owner, bystander.SessionIdHash, now)
	require.NoError(t, err)
	assert.NotNil(t, survivor, "the delete is keyed on one (owner, hash) and must reach no other row")

	// Deleting a session that is already gone is not an error: logout and identifier
	// rotation can both arrive at a row somebody else already removed.
	assert.NoError(t, database.DeleteBrowserSession(nil, target.Owner, target.SessionIdHash))
}

// TestBrowserSession_DeleteExpired asserts the reaper's predicate on both sides in one
// call, so a delete-everything cannot satisfy it.
func TestBrowserSession_DeleteExpired(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Microsecond)

	dead := createTestBrowserSession(t, ownerAuthServer, now.Add(-2*time.Hour), time.Hour) // expired an hour ago
	alive := createTestBrowserSession(t, ownerAuthServer, now, time.Hour)                  // expires in an hour
	deadOther := createTestBrowserSession(t, ownerAdminConsole, now.Add(-2*time.Hour), time.Hour)

	require.NoError(t, database.DeleteExpiredBrowserSessions(nil, now), "DeleteExpiredBrowserSessions")

	// Read the reaped rows back at a time before their own expiry, so what is asserted is
	// that the row is GONE rather than merely unreadable.
	early := now.Add(-3 * time.Hour)

	reaped, err := database.GetBrowserSessionByOwnerAndSessionIdHash(nil, dead.Owner, dead.SessionIdHash, early)
	require.NoError(t, err)
	assert.Nil(t, reaped, "an expired row must be deleted")

	reapedOther, err := database.GetBrowserSessionByOwnerAndSessionIdHash(nil, deadOther.Owner, deadOther.SessionIdHash, early)
	require.NoError(t, err)
	assert.Nil(t, reapedOther, "the reap crosses both owners")

	survivor, err := database.GetBrowserSessionByOwnerAndSessionIdHash(nil, alive.Owner, alive.SessionIdHash, now)
	require.NoError(t, err)
	assert.NotNil(t, survivor, "a row whose expires_at is still in the future must survive the sweep")
}

// TestBrowserSession_ExpiredRowIsAbsentAndCannotBeRevived is the `expires_at > now` term
// observed on the real engines. It is what makes the idle timeout and the maximum
// lifetime a request-time rule rather than a deletion schedule: without it a session
// would outlive every one of its own deadlines until a sweep happened to run, and a touch
// would push those deadlines forward for as long as anyone kept poking it.
//
// The three calls are made a second either side of the deadline rather than far from it,
// so what is pinned is a boundary and not a blanket refusal.
func TestBrowserSession_ExpiredRowIsAbsentAndCannotBeRevived(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Microsecond)
	expiry := now.Add(time.Hour)

	bs := createTestBrowserSession(t, ownerAuthServer, now, time.Hour)

	justBefore := expiry.Add(-time.Second)
	justAfter := expiry.Add(time.Second)

	// A second before the deadline all three calls succeed.
	live, err := database.GetBrowserSessionByOwnerAndSessionIdHash(nil, bs.Owner, bs.SessionIdHash, justBefore)
	require.NoError(t, err)
	require.NotNil(t, live, "one second before its expiry the session is still live")

	touched, err := database.TouchBrowserSession(nil, bs.Owner, bs.SessionIdHash, justBefore, expiry)
	require.NoError(t, err)
	assert.True(t, touched, "a live session can be touched")

	moved, err := database.UpdateBrowserSessionData(nil, bs.Owner, bs.SessionIdHash, "still live", justBefore, expiry)
	require.NoError(t, err)
	assert.True(t, moved, "a live session can be written")

	// A second after it, none of them do, and neither write moves the deadline.
	expired, err := database.GetBrowserSessionByOwnerAndSessionIdHash(nil, bs.Owner, bs.SessionIdHash, justAfter)
	require.NoError(t, err, "an expired row is absent, not an error")
	assert.Nil(t, expired, "one second after its expiry the session reads as absent")

	touched, err = database.TouchBrowserSession(nil, bs.Owner, bs.SessionIdHash, justAfter, justAfter.Add(time.Hour))
	require.NoError(t, err)
	assert.False(t, touched, "an expired session cannot be touched back to life")

	moved, err = database.UpdateBrowserSessionData(nil, bs.Owner, bs.SessionIdHash, "revived",
		justAfter, justAfter.Add(time.Hour))
	require.NoError(t, err)
	assert.False(t, moved, "an expired session cannot be written back to life")

	// And the row genuinely still carries its old deadline and its old contents, so the
	// false returns are not reporting a refusal after a write that landed anyway.
	raw := rawSQLHandle(t)
	row := raw.QueryRow(fmt.Sprintf(
		"SELECT data FROM browser_sessions WHERE id = %d", bs.Id))
	var data string
	require.NoError(t, row.Scan(&data))
	assert.Equal(t, "still live", data, "the refused writes must have left the row alone")

	stillExpired, err := database.GetBrowserSessionByOwnerAndSessionIdHash(nil, bs.Owner, bs.SessionIdHash, justAfter)
	require.NoError(t, err)
	assert.Nil(t, stillExpired, "the refused writes must not have moved expires_at forward")
}

// TestBrowserSession_StorageFailuresAreErrors is testing.md section 4's first question,
// for each of the six: a statement that could not execute must come back as an error and
// with the safe zero value beside it, never as a benign "no such session" or "nothing
// transitioned".
//
// It is the distinction decision 14 rests on. A lookup that failed is a refused request;
// a lookup that found nothing is a fresh session. Collapsing the first into the second
// would silently discard every session in flight during any database interruption, and
// hand anyone able to disrupt the database briefly a way to sign everybody out.
//
// A transaction that has already been rolled back is the deterministic way to make the
// statement fail on every engine: database/sql answers sql.ErrTxDone from tx.Exec and
// tx.Query itself, before any driver is reached, which is the mechanism
// TestUpdateKeyPairState_StorageFailureIsAnError established.
func TestBrowserSession_StorageFailuresAreErrors(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Microsecond)
	existing := createTestBrowserSession(t, ownerAuthServer, now, time.Hour)

	deadTx := func(t *testing.T) *sql.Tx {
		t.Helper()
		tx, err := database.BeginTransaction()
		require.NoError(t, err, "BeginTransaction")
		require.NoError(t, database.RollbackTransaction(tx), "RollbackTransaction")
		return tx
	}

	t.Run("CreateBrowserSession", func(t *testing.T) {
		bs := newBrowserSession(ownerAuthServer, now, time.Hour)
		assert.Error(t, database.CreateBrowserSession(deadTx(t), bs))
		assert.Zero(t, bs.Id, "a failed insert must report no id")
	})

	t.Run("GetBrowserSessionByOwnerAndSessionIdHash", func(t *testing.T) {
		got, err := database.GetBrowserSessionByOwnerAndSessionIdHash(deadTx(t),
			existing.Owner, existing.SessionIdHash, now)
		assert.Error(t, err, "a lookup that could not run is an error, not an absent session")
		assert.Nil(t, got)
	})

	t.Run("UpdateBrowserSessionData", func(t *testing.T) {
		moved, err := database.UpdateBrowserSessionData(deadTx(t),
			existing.Owner, existing.SessionIdHash, "x", now, now.Add(time.Hour))
		assert.Error(t, err)
		assert.False(t, moved, "a failed statement must not report a transition")
	})

	t.Run("TouchBrowserSession", func(t *testing.T) {
		touched, err := database.TouchBrowserSession(deadTx(t),
			existing.Owner, existing.SessionIdHash, now, now.Add(time.Hour))
		assert.Error(t, err)
		assert.False(t, touched)
	})

	t.Run("DeleteBrowserSession", func(t *testing.T) {
		assert.Error(t, database.DeleteBrowserSession(deadTx(t), existing.Owner, existing.SessionIdHash))
	})

	t.Run("DeleteExpiredBrowserSessions", func(t *testing.T) {
		assert.Error(t, database.DeleteExpiredBrowserSessions(deadTx(t), now))
	})

	// The row the failing statements named is untouched, so none of them reported a
	// failure after doing the work anyway.
	survivor, err := database.GetBrowserSessionByOwnerAndSessionIdHash(nil, existing.Owner, existing.SessionIdHash, now)
	require.NoError(t, err)
	require.NotNil(t, survivor, "the failed delete must not have removed the row")
	assert.Equal(t, existing.Data, survivor.Data, "the failed update must not have rewritten it")
}

// TestBrowserSession_EmptyKeyPartsAreRefused keeps the guard clauses as their own cases
// rather than letting them stand in for the storage-failure ones above. They return
// before a statement is built, so they can catch nothing about a query, a scan, an Exec
// or a RowsAffected that failed. DeleteExpiredBrowserSessions takes neither argument, so
// it has no empty-input case at all.
func TestBrowserSession_EmptyKeyPartsAreRefused(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Microsecond)
	hash := sha256Hex("some session")

	// No row carries an empty owner or an empty hash, so an empty value can only be a
	// caller bug. Matching on one would return somebody else's row, or sweep rows the
	// caller never named.
	bs := newBrowserSession("", now, time.Hour)
	assert.Error(t, database.CreateBrowserSession(nil, bs), "an empty owner must be refused")

	bs = newBrowserSession(ownerAuthServer, now, time.Hour)
	bs.SessionIdHash = ""
	assert.Error(t, database.CreateBrowserSession(nil, bs), "an empty session id hash must be refused")

	got, err := database.GetBrowserSessionByOwnerAndSessionIdHash(nil, "", hash, now)
	assert.Error(t, err)
	assert.Nil(t, got)
	got, err = database.GetBrowserSessionByOwnerAndSessionIdHash(nil, ownerAuthServer, "", now)
	assert.Error(t, err)
	assert.Nil(t, got)

	moved, err := database.UpdateBrowserSessionData(nil, "", hash, "x", now, now.Add(time.Hour))
	assert.Error(t, err)
	assert.False(t, moved)
	moved, err = database.UpdateBrowserSessionData(nil, ownerAuthServer, "", "x", now, now.Add(time.Hour))
	assert.Error(t, err)
	assert.False(t, moved)

	touched, err := database.TouchBrowserSession(nil, "", hash, now, now.Add(time.Hour))
	assert.Error(t, err)
	assert.False(t, touched)
	touched, err = database.TouchBrowserSession(nil, ownerAuthServer, "", now, now.Add(time.Hour))
	assert.Error(t, err)
	assert.False(t, touched)

	assert.Error(t, database.DeleteBrowserSession(nil, "", hash))
	assert.Error(t, database.DeleteBrowserSession(nil, ownerAuthServer, ""))
}

// TestBrowserSession_EnlistsInTheCallersTransaction is testing.md section 4's second
// question, and it cannot be written at any other tier: "was handed a *sql.Tx" is not the
// same claim as "used it", and a method that ignored its argument and ran on the pool
// would satisfy every mock in the tree.
//
// It is contract rather than a current caller: the store saves with a nil transaction
// today. A later caller batching a session write with another write would otherwise find
// half of it committed.
func TestBrowserSession_EnlistsInTheCallersTransaction(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Microsecond)

	t.Run("CreateBrowserSession", func(t *testing.T) {
		bs := newBrowserSession(ownerAuthServer, now, time.Hour)

		tx, err := database.BeginTransaction()
		require.NoError(t, err, "BeginTransaction")

		require.NoError(t, database.CreateBrowserSession(tx, bs), "CreateBrowserSession")

		inside, err := database.GetBrowserSessionByOwnerAndSessionIdHash(tx, bs.Owner, bs.SessionIdHash, now)
		require.NoError(t, err)
		assert.NotNil(t, inside, "inside the transaction the insert is visible to its own read-back")

		require.NoError(t, database.RollbackTransaction(tx), "RollbackTransaction")

		after, err := database.GetBrowserSessionByOwnerAndSessionIdHash(nil, bs.Owner, bs.SessionIdHash, now)
		require.NoError(t, err)
		assert.Nil(t, after, "a rolled back transaction must leave no row; if this is found, "+
			"the insert ran outside the caller's transaction")
	})

	t.Run("UpdateBrowserSessionData", func(t *testing.T) {
		bs := createTestBrowserSession(t, ownerAuthServer, now, time.Hour)

		tx, err := database.BeginTransaction()
		require.NoError(t, err, "BeginTransaction")

		moved, err := database.UpdateBrowserSessionData(tx, bs.Owner, bs.SessionIdHash, "rewritten",
			now, now.Add(2*time.Hour))
		require.NoError(t, err)
		require.True(t, moved)

		require.NoError(t, database.RollbackTransaction(tx), "RollbackTransaction")

		after, err := database.GetBrowserSessionByOwnerAndSessionIdHash(nil, bs.Owner, bs.SessionIdHash, now)
		require.NoError(t, err)
		require.NotNil(t, after)
		assert.Equal(t, bs.Data, after.Data, "a rolled back transaction must leave the contents where they were")
	})

	t.Run("DeleteBrowserSession", func(t *testing.T) {
		bs := createTestBrowserSession(t, ownerAuthServer, now, time.Hour)

		tx, err := database.BeginTransaction()
		require.NoError(t, err, "BeginTransaction")

		require.NoError(t, database.DeleteBrowserSession(tx, bs.Owner, bs.SessionIdHash))
		require.NoError(t, database.RollbackTransaction(tx), "RollbackTransaction")

		after, err := database.GetBrowserSessionByOwnerAndSessionIdHash(nil, bs.Owner, bs.SessionIdHash, now)
		require.NoError(t, err)
		assert.NotNil(t, after, "a rolled back delete must leave the row in place")
	})
}
