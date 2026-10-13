package sessionbackend

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	"github.com/leodip/goiabada/authserver/internal/data/mocks"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/authserver/internal/sessionkeys"
	"github.com/leodip/goiabada/core/hashutil"
	"github.com/leodip/goiabada/core/sessionstore"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// The conditional pair carries the contents the store's fresh read returned to the statement's
// WHERE, beside the owner and the digest, and reads a row that did not transition as
// sessionstore.ErrChanged (#579).

func TestDatabaseBackend_UpdateIfUnchanged(t *testing.T) {
	const (
		owner = "owner"
		id    = "conditional-update-id"
	)
	hash := hashutil.HashString(id)
	createdAt := fixedNow.Add(-time.Hour)
	wantExpiry := fixedNow.Add(30 * time.Minute)

	t.Run("passes the contents read and computes the deadline as Update does", func(t *testing.T) {
		database := datamocks.NewDatabase(t)
		database.EXPECT().GetBrowserSessionByOwnerAndSessionIdHash(mock.Anything, (*sql.Tx)(nil), owner, hash, fixedNow).
			Return(&record.BrowserSession{CreatedAt: sql.NullTime{Time: createdAt, Valid: true}}, nil)
		database.EXPECT().UpdateBrowserSessionDataIfUnchanged(mock.Anything, (*sql.Tx)(nil), owner, hash,
			"what was read", "ciphertext", fixedNow, wantExpiry).Return(true, nil)

		expiresAt, err := testBackend(database, owner).UpdateIfUnchanged(settingsContext(), id,
			[]byte("what was read"), []byte("ciphertext"), true)

		require.NoError(t, err)
		assert.Equal(t, wantExpiry, expiresAt)
	})

	t.Run("no transition is changed", func(t *testing.T) {
		database := datamocks.NewDatabase(t)
		want := fixedNow.Add(sessionstore.PreAuthLifetime)
		database.EXPECT().UpdateBrowserSessionDataIfUnchanged(mock.Anything, (*sql.Tx)(nil), owner, hash,
			"what was read", "ciphertext", fixedNow, want).Return(false, nil)

		_, err := testBackend(database, owner).UpdateIfUnchanged(context.Background(), id,
			[]byte("what was read"), []byte("ciphertext"), false)

		require.ErrorIs(t, err, sessionstore.ErrChanged)
	})

	t.Run("unauthenticated reads nothing", func(t *testing.T) {
		database := datamocks.NewDatabase(t)
		want := fixedNow.Add(sessionstore.PreAuthLifetime)
		database.EXPECT().UpdateBrowserSessionDataIfUnchanged(mock.Anything, (*sql.Tx)(nil), owner, hash,
			"what was read", "ciphertext", fixedNow, want).Return(true, nil)

		expiresAt, err := testBackend(database, owner).UpdateIfUnchanged(context.Background(), id,
			[]byte("what was read"), []byte("ciphertext"), false)

		require.NoError(t, err)
		assert.Equal(t, want, expiresAt)
		database.AssertNotCalled(t, "GetBrowserSessionByOwnerAndSessionIdHash", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything)
	})

	t.Run("absent pre-read is not found and writes nothing", func(t *testing.T) {
		database := datamocks.NewDatabase(t)
		database.EXPECT().GetBrowserSessionByOwnerAndSessionIdHash(mock.Anything, (*sql.Tx)(nil), owner, hash, fixedNow).
			Return(nil, nil)

		_, err := testBackend(database, owner).UpdateIfUnchanged(settingsContext(), id,
			[]byte("what was read"), []byte("ciphertext"), true)

		require.ErrorIs(t, err, sessionstore.ErrNotFound)
		database.AssertNotCalled(t, "UpdateBrowserSessionDataIfUnchanged", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything)
	})

	t.Run("write failure wraps its cause", func(t *testing.T) {
		cause := errors.New("update failed")
		database := datamocks.NewDatabase(t)
		database.EXPECT().UpdateBrowserSessionDataIfUnchanged(mock.Anything, (*sql.Tx)(nil), owner, hash,
			"what was read", "ciphertext", fixedNow, fixedNow.Add(sessionstore.PreAuthLifetime)).Return(false, cause)

		_, err := testBackend(database, owner).UpdateIfUnchanged(context.Background(), id,
			[]byte("what was read"), []byte("ciphertext"), false)

		requireWrappedCause(t, err, cause)
		assert.NotErrorIs(t, err, sessionstore.ErrChanged, "a failure is not a lost race")
	})
}

func TestDatabaseBackend_DeleteIfUnchanged(t *testing.T) {
	const (
		owner = "owner"
		id    = "conditional-delete-id"
	)
	hash := hashutil.HashString(id)

	t.Run("passes owner, digest, the contents read and now", func(t *testing.T) {
		database := datamocks.NewDatabase(t)
		database.EXPECT().DeleteBrowserSessionIfUnchanged(mock.Anything, (*sql.Tx)(nil), owner, hash, "what was read", fixedNow).
			Return(true, nil)

		require.NoError(t, testBackend(database, owner).DeleteIfUnchanged(context.Background(), id, []byte("what was read")))
	})

	t.Run("nothing removed is changed", func(t *testing.T) {
		database := datamocks.NewDatabase(t)
		database.EXPECT().DeleteBrowserSessionIfUnchanged(mock.Anything, (*sql.Tx)(nil), owner, hash, "what was read", fixedNow).
			Return(false, nil)

		err := testBackend(database, owner).DeleteIfUnchanged(context.Background(), id, []byte("what was read"))

		require.ErrorIs(t, err, sessionstore.ErrChanged)
	})

	t.Run("wraps a failure", func(t *testing.T) {
		cause := errors.New("delete failed")
		database := datamocks.NewDatabase(t)
		database.EXPECT().DeleteBrowserSessionIfUnchanged(mock.Anything, (*sql.Tx)(nil), owner, hash, "what was read", fixedNow).
			Return(false, cause)

		err := testBackend(database, owner).DeleteIfUnchanged(context.Background(), id, []byte("what was read"))

		requireWrappedCause(t, err, cause)
		assert.NotErrorIs(t, err, sessionstore.ErrChanged, "a failure is not a lost race")
	})
}

// Both statements are issued under the context the store handed down, as every other one is.
func TestDatabaseBackend_ConditionalWritesUnderTheCallersContext(t *testing.T) {
	const owner, id = "owner", "propagation-conditional"
	hash := hashutil.HashString(id)

	t.Run("update", func(t *testing.T) {
		database := datamocks.NewDatabase(t)
		database.On("UpdateBrowserSessionDataIfUnchanged", theCallersContext(), (*sql.Tx)(nil), owner, hash,
			"read", "data", fixedNow, mock.Anything).Return(true, nil).Once()

		_, err := testBackend(database, owner).UpdateIfUnchanged(markedSettingsContext(), id, []byte("read"), []byte("data"), false)

		require.NoError(t, err)
		database.AssertExpectations(t)
	})

	t.Run("delete", func(t *testing.T) {
		database := datamocks.NewDatabase(t)
		database.On("DeleteBrowserSessionIfUnchanged", theCallersContext(), (*sql.Tx)(nil), owner, hash, "read", fixedNow).
			Return(true, nil).Once()

		require.NoError(t, testBackend(database, owner).DeleteIfUnchanged(markedSettingsContext(), id, []byte("read")))
		database.AssertExpectations(t)
	})
}

// The auth server's constructor fixes the owner of the conditional pair too, so no conditional
// write can name an admin console row.
func TestDatabaseBackend_AuthServerConstructorFixesTheConditionalOwner(t *testing.T) {
	t.Run("update", func(t *testing.T) {
		database := datamocks.NewDatabase(t)
		database.EXPECT().UpdateBrowserSessionDataIfUnchanged(mock.Anything, (*sql.Tx)(nil), sessionkeys.AuthServerSessionName,
			mock.Anything, "read", "data", mock.Anything, mock.Anything).Return(true, nil)
		_, err := NewAuthServerBackend(database).UpdateIfUnchanged(context.Background(), "id", []byte("read"), []byte("data"), false)
		require.NoError(t, err)
	})
	t.Run("delete", func(t *testing.T) {
		database := datamocks.NewDatabase(t)
		database.EXPECT().DeleteBrowserSessionIfUnchanged(mock.Anything, (*sql.Tx)(nil), sessionkeys.AuthServerSessionName,
			mock.Anything, "read", mock.Anything).Return(true, nil)
		require.NoError(t, NewAuthServerBackend(database).DeleteIfUnchanged(context.Background(), "id", []byte("read")))
	})
}
