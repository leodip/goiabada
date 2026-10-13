package datatests

import (
	"context"
	"database/sql"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The conditional pair of #579: an update and a delete of a browser session that take effect only
// while the row's data is the value a fresh read returned. Only a real engine shows that the
// comparison is exact on its text type and collation, which is the whole of the condition.

func loadBrowserSession(t *testing.T, owner, hash string, now time.Time) string {
	t.Helper()
	loaded, err := database.GetBrowserSessionByOwnerAndSessionIdHash(context.Background(), nil, owner, hash, now)
	require.NoError(t, err)
	require.NotNil(t, loaded, "the session must still be there")
	return loaded.Data
}

func TestBrowserSession_UpdateIfUnchangedWritesWhileTheDataIsTheOneRead(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Microsecond)
	bs := createTestBrowserSession(t, ownerAuthServer, now, time.Hour)

	moved, err := database.UpdateBrowserSessionDataIfUnchanged(context.Background(), nil, bs.Owner, bs.SessionIdHash,
		bs.Data, "new contents", now.Add(time.Minute), now.Add(3*time.Hour))
	require.NoError(t, err)
	assert.True(t, moved, "an unchanged live row transitions")

	loaded, err := database.GetBrowserSessionByOwnerAndSessionIdHash(context.Background(), nil, bs.Owner, bs.SessionIdHash, now)
	require.NoError(t, err)
	require.NotNil(t, loaded)
	assert.Equal(t, "new contents", loaded.Data)
	assert.WithinDuration(t, now.Add(time.Minute), loaded.LastAccessed, time.Second)
	assert.WithinDuration(t, now.Add(3*time.Hour), loaded.ExpiresAt, time.Second)
}

// The session's largest real contents are about 13 KB, so the condition has to hold past any
// short-string comparison an engine might special-case.
func TestBrowserSession_UpdateIfUnchangedComparesLargeData(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Microsecond)
	bs := newBrowserSession(ownerAuthServer, now, time.Hour)
	bs.Data = strings.Repeat("x", 64*1024)
	require.NoError(t, database.CreateBrowserSession(context.Background(), nil, bs))

	almost := strings.Repeat("x", 64*1024-1) + "y"
	moved, err := database.UpdateBrowserSessionDataIfUnchanged(context.Background(), nil, bs.Owner, bs.SessionIdHash,
		almost, "lost", now, now.Add(time.Hour))
	require.NoError(t, err)
	assert.False(t, moved, "data differing in its last character is not the data read")

	moved, err = database.UpdateBrowserSessionDataIfUnchanged(context.Background(), nil, bs.Owner, bs.SessionIdHash,
		bs.Data, "won", now, now.Add(time.Hour))
	require.NoError(t, err)
	assert.True(t, moved)
	assert.Equal(t, "won", loadBrowserSession(t, bs.Owner, bs.SessionIdHash, now))
}

func TestBrowserSession_UpdateIfUnchangedAfterAnotherWriteWritesNothing(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Microsecond)
	bs := createTestBrowserSession(t, ownerAuthServer, now, time.Hour)

	moved, err := database.UpdateBrowserSessionData(context.Background(), nil, bs.Owner, bs.SessionIdHash,
		"another request's", now, now.Add(2*time.Hour))
	require.NoError(t, err)
	require.True(t, moved)

	moved, err = database.UpdateBrowserSessionDataIfUnchanged(context.Background(), nil, bs.Owner, bs.SessionIdHash,
		bs.Data, "stale write", now.Add(time.Minute), now.Add(5*time.Hour))
	require.NoError(t, err)
	assert.False(t, moved, "a row written since the read does not transition")

	loaded, err := database.GetBrowserSessionByOwnerAndSessionIdHash(context.Background(), nil, bs.Owner, bs.SessionIdHash, now)
	require.NoError(t, err)
	require.NotNil(t, loaded)
	assert.Equal(t, "another request's", loaded.Data)
	assert.WithinDuration(t, now.Add(2*time.Hour), loaded.ExpiresAt, time.Second, "the refused write did not move the deadline")
}

// Equality is exact on every engine: the column's collation is case and accent sensitive on MySQL
// and SQL Server, deterministic on PostgreSQL and BINARY on SQLite. The sealed value is
// base64url, where case carries the bits.
func TestBrowserSession_UpdateIfUnchangedIsCaseSensitive(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Microsecond)
	bs := newBrowserSession(ownerAuthServer, now, time.Hour)
	bs.Data = "AbCdEf-_0123"
	require.NoError(t, database.CreateBrowserSession(context.Background(), nil, bs))

	moved, err := database.UpdateBrowserSessionDataIfUnchanged(context.Background(), nil, bs.Owner, bs.SessionIdHash,
		"abcdef-_0123", "lost", now, now.Add(time.Hour))
	require.NoError(t, err)
	assert.False(t, moved, "data differing only in case is not the data read")
	assert.Equal(t, "AbCdEf-_0123", loadBrowserSession(t, bs.Owner, bs.SessionIdHash, now))
}

// A touch moves the timestamps and not the data, so it never makes a conditional write lose.
func TestBrowserSession_UpdateIfUnchangedAfterATouchStillWrites(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Microsecond)
	bs := createTestBrowserSession(t, ownerAuthServer, now, time.Hour)

	touched, err := database.TouchBrowserSession(context.Background(), nil, bs.Owner, bs.SessionIdHash,
		now.Add(time.Minute), now.Add(2*time.Hour))
	require.NoError(t, err)
	require.True(t, touched)

	moved, err := database.UpdateBrowserSessionDataIfUnchanged(context.Background(), nil, bs.Owner, bs.SessionIdHash,
		bs.Data, "new contents", now.Add(2*time.Minute), now.Add(3*time.Hour))
	require.NoError(t, err)
	assert.True(t, moved)
	assert.Equal(t, "new contents", loadBrowserSession(t, bs.Owner, bs.SessionIdHash, now))
}

func TestBrowserSession_UpdateIfUnchangedOfAGoneRowWritesNothing(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Microsecond)

	t.Run("absent", func(t *testing.T) {
		moved, err := database.UpdateBrowserSessionDataIfUnchanged(context.Background(), nil, ownerAuthServer,
			sha256Hex("no such session"), "x", "y", now, now.Add(time.Hour))
		require.NoError(t, err)
		assert.False(t, moved)
	})

	t.Run("expired", func(t *testing.T) {
		bs := createTestBrowserSession(t, ownerAuthServer, now.Add(-2*time.Hour), time.Hour)

		moved, err := database.UpdateBrowserSessionDataIfUnchanged(context.Background(), nil, bs.Owner, bs.SessionIdHash,
			bs.Data, "revived", now, now.Add(time.Hour))
		require.NoError(t, err)
		assert.False(t, moved, "an expired row is no such session, unchanged or not")

		after, err := database.GetBrowserSessionByOwnerAndSessionIdHash(context.Background(), nil, bs.Owner, bs.SessionIdHash, now)
		require.NoError(t, err)
		assert.Nil(t, after, "the refused write did not touch the row back to life")
	})

	t.Run("another owner's", func(t *testing.T) {
		bs := createTestBrowserSession(t, ownerAdminConsole, now, time.Hour)

		moved, err := database.UpdateBrowserSessionDataIfUnchanged(context.Background(), nil, ownerAuthServer, bs.SessionIdHash,
			bs.Data, "crossed over", now, now.Add(time.Hour))
		require.NoError(t, err)
		assert.False(t, moved)
		assert.Equal(t, bs.Data, loadBrowserSession(t, ownerAdminConsole, bs.SessionIdHash, now))
	})
}

func TestBrowserSession_DeleteIfUnchangedRemovesTheRowRead(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Microsecond)
	bs := createTestBrowserSession(t, ownerAuthServer, now, time.Hour)

	deleted, err := database.DeleteBrowserSessionIfUnchanged(context.Background(), nil, bs.Owner, bs.SessionIdHash, bs.Data, now)
	require.NoError(t, err)
	assert.True(t, deleted)

	after, err := database.GetBrowserSessionByOwnerAndSessionIdHash(context.Background(), nil, bs.Owner, bs.SessionIdHash, now)
	require.NoError(t, err)
	assert.Nil(t, after)
}

func TestBrowserSession_DeleteIfUnchangedAfterAnotherWriteKeepsTheRow(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Microsecond)
	bs := createTestBrowserSession(t, ownerAuthServer, now, time.Hour)

	moved, err := database.UpdateBrowserSessionData(context.Background(), nil, bs.Owner, bs.SessionIdHash,
		"another request's", now, now.Add(time.Hour))
	require.NoError(t, err)
	require.True(t, moved)

	deleted, err := database.DeleteBrowserSessionIfUnchanged(context.Background(), nil, bs.Owner, bs.SessionIdHash, bs.Data, now)
	require.NoError(t, err)
	assert.False(t, deleted)
	assert.Equal(t, "another request's", loadBrowserSession(t, bs.Owner, bs.SessionIdHash, now))
}

func TestBrowserSession_DeleteIfUnchangedOfAGoneRowReportsNothingRemoved(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Microsecond)

	t.Run("absent", func(t *testing.T) {
		deleted, err := database.DeleteBrowserSessionIfUnchanged(context.Background(), nil, ownerAuthServer,
			sha256Hex("no such session"), "x", now)
		require.NoError(t, err)
		assert.False(t, deleted)
	})

	t.Run("expired", func(t *testing.T) {
		bs := createTestBrowserSession(t, ownerAuthServer, now.Add(-2*time.Hour), time.Hour)

		deleted, err := database.DeleteBrowserSessionIfUnchanged(context.Background(), nil, bs.Owner, bs.SessionIdHash, bs.Data, now)
		require.NoError(t, err)
		assert.False(t, deleted, "an expired row is no such session to rotate away")
	})

	t.Run("another owner's", func(t *testing.T) {
		bs := createTestBrowserSession(t, ownerAdminConsole, now, time.Hour)

		deleted, err := database.DeleteBrowserSessionIfUnchanged(context.Background(), nil, ownerAuthServer, bs.SessionIdHash, bs.Data, now)
		require.NoError(t, err)
		assert.False(t, deleted)
		assert.Equal(t, bs.Data, loadBrowserSession(t, ownerAdminConsole, bs.SessionIdHash, now))
	})
}

func TestBrowserSession_ConditionalStorageFailuresAreErrors(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Microsecond)
	existing := createTestBrowserSession(t, ownerAuthServer, now, time.Hour)

	deadTx := func(t *testing.T) *sql.Tx {
		t.Helper()
		tx, err := database.BeginTransaction(context.Background())
		require.NoError(t, err, "BeginTransaction")
		require.NoError(t, database.RollbackTransaction(context.Background(), tx), "RollbackTransaction")
		return tx
	}

	moved, err := database.UpdateBrowserSessionDataIfUnchanged(context.Background(), deadTx(t), existing.Owner,
		existing.SessionIdHash, existing.Data, "x", now, now.Add(time.Hour))
	require.Error(t, err)
	assert.False(t, moved, "a failed statement must not report a transition")

	deleted, err := database.DeleteBrowserSessionIfUnchanged(context.Background(), deadTx(t), existing.Owner,
		existing.SessionIdHash, existing.Data, now)
	require.Error(t, err)
	assert.False(t, deleted)

	assert.Equal(t, existing.Data, loadBrowserSession(t, existing.Owner, existing.SessionIdHash, now),
		"neither failed statement did its work anyway")
}

func TestBrowserSession_ConditionalEmptyKeyPartsAreRefused(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Microsecond)
	hash := sha256Hex("some session")

	moved, err := database.UpdateBrowserSessionDataIfUnchanged(context.Background(), nil, "", hash, "x", "y", now, now.Add(time.Hour))
	require.Error(t, err)
	assert.False(t, moved)
	moved, err = database.UpdateBrowserSessionDataIfUnchanged(context.Background(), nil, ownerAuthServer, "", "x", "y", now, now.Add(time.Hour))
	require.Error(t, err)
	assert.False(t, moved)

	deleted, err := database.DeleteBrowserSessionIfUnchanged(context.Background(), nil, "", hash, "x", now)
	require.Error(t, err)
	assert.False(t, deleted)
	deleted, err = database.DeleteBrowserSessionIfUnchanged(context.Background(), nil, ownerAuthServer, "", "x", now)
	require.Error(t, err)
	assert.False(t, deleted)
}

func TestBrowserSession_ConditionalEnlistsInTheCallersTransaction(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Microsecond)

	t.Run("UpdateBrowserSessionDataIfUnchanged", func(t *testing.T) {
		bs := createTestBrowserSession(t, ownerAuthServer, now, time.Hour)

		tx, err := database.BeginTransaction(context.Background())
		require.NoError(t, err, "BeginTransaction")
		// A failure below must not leave the transaction holding SQLite's one connection.
		defer func() { _ = database.RollbackTransaction(context.Background(), tx) }()
		moved, err := database.UpdateBrowserSessionDataIfUnchanged(context.Background(), tx, bs.Owner, bs.SessionIdHash,
			bs.Data, "rewritten", now, now.Add(2*time.Hour))
		require.NoError(t, err)
		require.True(t, moved)
		require.NoError(t, database.RollbackTransaction(context.Background(), tx), "RollbackTransaction")

		assert.Equal(t, bs.Data, loadBrowserSession(t, bs.Owner, bs.SessionIdHash, now),
			"a rolled back transaction must leave the contents where they were")
	})

	t.Run("DeleteBrowserSessionIfUnchanged", func(t *testing.T) {
		bs := createTestBrowserSession(t, ownerAuthServer, now, time.Hour)

		tx, err := database.BeginTransaction(context.Background())
		require.NoError(t, err, "BeginTransaction")
		defer func() { _ = database.RollbackTransaction(context.Background(), tx) }()
		deleted, err := database.DeleteBrowserSessionIfUnchanged(context.Background(), tx, bs.Owner, bs.SessionIdHash, bs.Data, now)
		require.NoError(t, err)
		require.True(t, deleted)
		require.NoError(t, database.RollbackTransaction(context.Background(), tx), "RollbackTransaction")

		assert.Equal(t, bs.Data, loadBrowserSession(t, bs.Owner, bs.SessionIdHash, now),
			"a rolled back delete must leave the row in place")
	})
}
