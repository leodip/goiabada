package sessionbackend

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	"github.com/leodip/goiabada/authserver/internal/constants"
	mocks_data "github.com/leodip/goiabada/authserver/internal/data/mocks"
	coreconstants "github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/models"
	"github.com/leodip/goiabada/core/sessionstore"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

var fixedNow = time.Date(2026, time.September, 13, 12, 0, 0, 0, time.UTC)

func testSettings() *models.Settings {
	return &models.Settings{
		UserSessionIdleTimeoutInSeconds: 2 * 60 * 60,
		UserSessionMaxLifetimeInSeconds: 90 * 60,
	}
}

func settingsContext() context.Context {
	return context.WithValue(context.Background(), constants.ContextKeySettings, testSettings())
}

func testBackend(database *mocks_data.Database, owner string) *dbBackend {
	backend := newBackend(database, owner)
	backend.now = func() time.Time { return fixedNow }
	return backend
}

func requireWrappedCause(t *testing.T, err, cause error) {
	t.Helper()
	require.Error(t, err)
	assert.ErrorIs(t, err, cause)
	assert.NotErrorIs(t, err, sessionstore.ErrNotFound)
}

func TestDatabaseBackend_Load(t *testing.T) {
	const (
		owner = "owner"
		id    = "load-id"
	)

	t.Run("maps a row", func(t *testing.T) {
		database := mocks_data.NewDatabase(t)
		row := &models.BrowserSession{
			Data:          "ciphertext",
			LastAccessed:  fixedNow.Add(-time.Minute),
			ExpiresAt:     fixedNow.Add(time.Hour),
			SessionIdHash: hashSessionId(id),
		}
		database.EXPECT().GetBrowserSessionByOwnerAndSessionIdHash((*sql.Tx)(nil), owner, hashSessionId(id), fixedNow).
			Return(row, nil)

		record, err := testBackend(database, owner).Load(context.Background(), id)

		require.NoError(t, err)
		assert.Equal(t, []byte("ciphertext"), record.Data)
		assert.Equal(t, row.LastAccessed, record.LastAccessed)
		assert.Equal(t, row.ExpiresAt, record.ExpiresAt)
	})

	t.Run("maps an absent row to not found", func(t *testing.T) {
		database := mocks_data.NewDatabase(t)
		database.EXPECT().GetBrowserSessionByOwnerAndSessionIdHash((*sql.Tx)(nil), owner, hashSessionId(id), fixedNow).
			Return(nil, nil)

		record, err := testBackend(database, owner).Load(context.Background(), id)

		assert.Nil(t, record)
		assert.ErrorIs(t, err, sessionstore.ErrNotFound)
	})

	t.Run("wraps a failed read", func(t *testing.T) {
		cause := errors.New("read failed")
		database := mocks_data.NewDatabase(t)
		database.EXPECT().GetBrowserSessionByOwnerAndSessionIdHash((*sql.Tx)(nil), owner, hashSessionId(id), fixedNow).
			Return(nil, cause)

		record, err := testBackend(database, owner).Load(context.Background(), id)

		assert.Nil(t, record)
		requireWrappedCause(t, err, cause)
	})
}

func TestDatabaseBackend_Create(t *testing.T) {
	const (
		owner = "owner"
		id    = "create-id"
	)

	for _, tc := range []struct {
		name          string
		authenticated bool
		wantExpiry    time.Time
	}{
		{name: "unauthenticated deadline", wantExpiry: fixedNow.Add(sessionstore.PreAuthLifetime)},
		{name: "authenticated deadline", authenticated: true, wantExpiry: fixedNow.Add(90 * time.Minute)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			database := mocks_data.NewDatabase(t)
			database.EXPECT().CreateBrowserSession((*sql.Tx)(nil), mock.MatchedBy(func(row *models.BrowserSession) bool {
				return row.Owner == owner &&
					row.SessionId == id &&
					row.SessionIdHash == hashSessionId(id) &&
					row.Data == "ciphertext" &&
					row.LastAccessed.Equal(fixedNow) &&
					row.ExpiresAt.Equal(tc.wantExpiry)
			})).Return(nil)

			expiresAt, err := testBackend(database, owner).Create(settingsContext(), id, []byte("ciphertext"), tc.authenticated)

			require.NoError(t, err)
			assert.Equal(t, tc.wantExpiry, expiresAt)
		})
	}

	t.Run("wraps a failed insert", func(t *testing.T) {
		cause := errors.New("insert failed")
		database := mocks_data.NewDatabase(t)
		database.EXPECT().CreateBrowserSession((*sql.Tx)(nil), mock.Anything).Return(cause)

		expiresAt, err := testBackend(database, owner).Create(settingsContext(), id, []byte("ciphertext"), true)

		assert.True(t, expiresAt.IsZero())
		requireWrappedCause(t, err, cause)
	})
}

func TestDatabaseBackend_Update(t *testing.T) {
	const (
		owner = "owner"
		id    = "update-id"
	)
	hash := hashSessionId(id)
	createdAt := fixedNow.Add(-time.Hour)
	wantExpiry := fixedNow.Add(30 * time.Minute)

	t.Run("authenticated reads created at", func(t *testing.T) {
		database := mocks_data.NewDatabase(t)
		database.EXPECT().GetBrowserSessionByOwnerAndSessionIdHash((*sql.Tx)(nil), owner, hash, fixedNow).
			Return(&models.BrowserSession{CreatedAt: sql.NullTime{Time: createdAt, Valid: true}}, nil)
		database.EXPECT().UpdateBrowserSessionData((*sql.Tx)(nil), owner, hash, "ciphertext", fixedNow, wantExpiry).
			Return(true, nil)

		expiresAt, err := testBackend(database, owner).Update(settingsContext(), id, []byte("ciphertext"), true)

		require.NoError(t, err)
		assert.Equal(t, wantExpiry, expiresAt)
	})

	t.Run("absent write is not found", func(t *testing.T) {
		database := mocks_data.NewDatabase(t)
		database.EXPECT().GetBrowserSessionByOwnerAndSessionIdHash((*sql.Tx)(nil), owner, hash, fixedNow).
			Return(&models.BrowserSession{CreatedAt: sql.NullTime{Time: createdAt, Valid: true}}, nil)
		database.EXPECT().UpdateBrowserSessionData((*sql.Tx)(nil), owner, hash, "ciphertext", fixedNow, wantExpiry).
			Return(false, nil)

		_, err := testBackend(database, owner).Update(settingsContext(), id, []byte("ciphertext"), true)

		assert.ErrorIs(t, err, sessionstore.ErrNotFound)
	})

	t.Run("failed pre-read wraps", func(t *testing.T) {
		cause := errors.New("pre-read failed")
		database := mocks_data.NewDatabase(t)
		database.EXPECT().GetBrowserSessionByOwnerAndSessionIdHash((*sql.Tx)(nil), owner, hash, fixedNow).
			Return(nil, cause)

		_, err := testBackend(database, owner).Update(settingsContext(), id, []byte("ciphertext"), true)

		requireWrappedCause(t, err, cause)
		database.AssertNotCalled(t, "UpdateBrowserSessionData", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything)
	})

	t.Run("absent pre-read is not found", func(t *testing.T) {
		database := mocks_data.NewDatabase(t)
		database.EXPECT().GetBrowserSessionByOwnerAndSessionIdHash((*sql.Tx)(nil), owner, hash, fixedNow).
			Return(nil, nil)

		_, err := testBackend(database, owner).Update(settingsContext(), id, []byte("ciphertext"), true)

		assert.ErrorIs(t, err, sessionstore.ErrNotFound)
		database.AssertNotCalled(t, "UpdateBrowserSessionData", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything)
	})

	t.Run("unauthenticated reads nothing", func(t *testing.T) {
		database := mocks_data.NewDatabase(t)
		want := fixedNow.Add(sessionstore.PreAuthLifetime)
		database.EXPECT().UpdateBrowserSessionData((*sql.Tx)(nil), owner, hash, "ciphertext", fixedNow, want).
			Return(true, nil)

		expiresAt, err := testBackend(database, owner).Update(context.Background(), id, []byte("ciphertext"), false)

		require.NoError(t, err)
		assert.Equal(t, want, expiresAt)
		database.AssertNotCalled(t, "GetBrowserSessionByOwnerAndSessionIdHash", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
		database.AssertNotCalled(t, "GetSettingsById", mock.Anything, mock.Anything)
	})

	t.Run("write failure wraps its cause", func(t *testing.T) {
		cause := errors.New("update failed")
		database := mocks_data.NewDatabase(t)
		want := fixedNow.Add(sessionstore.PreAuthLifetime)
		database.EXPECT().UpdateBrowserSessionData((*sql.Tx)(nil), owner, hash, "ciphertext", fixedNow, want).
			Return(false, cause)

		_, err := testBackend(database, owner).Update(context.Background(), id, []byte("ciphertext"), false)

		requireWrappedCause(t, err, cause)
	})
}

func TestDatabaseBackend_Touch(t *testing.T) {
	const (
		owner = "owner"
		id    = "touch-id"
	)
	hash := hashSessionId(id)
	createdAt := fixedNow.Add(-time.Hour)
	wantExpiry := fixedNow.Add(30 * time.Minute)

	t.Run("authenticated reads created at", func(t *testing.T) {
		database := mocks_data.NewDatabase(t)
		database.EXPECT().GetBrowserSessionByOwnerAndSessionIdHash((*sql.Tx)(nil), owner, hash, fixedNow).
			Return(&models.BrowserSession{CreatedAt: sql.NullTime{Time: createdAt, Valid: true}}, nil)
		database.EXPECT().TouchBrowserSession((*sql.Tx)(nil), owner, hash, fixedNow, wantExpiry).Return(true, nil)

		expiresAt, err := testBackend(database, owner).Touch(settingsContext(), id, true)

		require.NoError(t, err)
		assert.Equal(t, wantExpiry, expiresAt)
	})

	t.Run("absent write is not found", func(t *testing.T) {
		database := mocks_data.NewDatabase(t)
		database.EXPECT().GetBrowserSessionByOwnerAndSessionIdHash((*sql.Tx)(nil), owner, hash, fixedNow).
			Return(&models.BrowserSession{CreatedAt: sql.NullTime{Time: createdAt, Valid: true}}, nil)
		database.EXPECT().TouchBrowserSession((*sql.Tx)(nil), owner, hash, fixedNow, wantExpiry).Return(false, nil)

		_, err := testBackend(database, owner).Touch(settingsContext(), id, true)

		assert.ErrorIs(t, err, sessionstore.ErrNotFound)
	})

	t.Run("failed pre-read wraps", func(t *testing.T) {
		cause := errors.New("pre-read failed")
		database := mocks_data.NewDatabase(t)
		database.EXPECT().GetBrowserSessionByOwnerAndSessionIdHash((*sql.Tx)(nil), owner, hash, fixedNow).
			Return(nil, cause)

		_, err := testBackend(database, owner).Touch(settingsContext(), id, true)

		requireWrappedCause(t, err, cause)
		database.AssertNotCalled(t, "TouchBrowserSession", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything)
	})

	t.Run("absent pre-read is not found", func(t *testing.T) {
		database := mocks_data.NewDatabase(t)
		database.EXPECT().GetBrowserSessionByOwnerAndSessionIdHash((*sql.Tx)(nil), owner, hash, fixedNow).
			Return(nil, nil)

		_, err := testBackend(database, owner).Touch(settingsContext(), id, true)

		assert.ErrorIs(t, err, sessionstore.ErrNotFound)
		database.AssertNotCalled(t, "TouchBrowserSession", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything)
	})

	t.Run("unauthenticated reads nothing", func(t *testing.T) {
		database := mocks_data.NewDatabase(t)
		want := fixedNow.Add(sessionstore.PreAuthLifetime)
		database.EXPECT().TouchBrowserSession((*sql.Tx)(nil), owner, hash, fixedNow, want).Return(true, nil)

		expiresAt, err := testBackend(database, owner).Touch(context.Background(), id, false)

		require.NoError(t, err)
		assert.Equal(t, want, expiresAt)
		database.AssertNotCalled(t, "GetBrowserSessionByOwnerAndSessionIdHash", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
		database.AssertNotCalled(t, "GetSettingsById", mock.Anything, mock.Anything)
	})

	t.Run("write failure wraps its cause", func(t *testing.T) {
		cause := errors.New("touch failed")
		database := mocks_data.NewDatabase(t)
		want := fixedNow.Add(sessionstore.PreAuthLifetime)
		database.EXPECT().TouchBrowserSession((*sql.Tx)(nil), owner, hash, fixedNow, want).Return(false, cause)

		_, err := testBackend(database, owner).Touch(context.Background(), id, false)

		requireWrappedCause(t, err, cause)
	})
}

func TestDatabaseBackend_InvalidCreatedAtFallsBackToNow(t *testing.T) {
	const (
		owner = "owner"
		id    = "invalid-created-at"
	)
	hash := hashSessionId(id)
	wantExpiry := fixedNow.Add(90 * time.Minute)

	for _, tc := range []struct {
		name  string
		write func(*mocks_data.Database)
		call  func(*dbBackend) (time.Time, error)
	}{
		{
			name: "update",
			write: func(database *mocks_data.Database) {
				database.EXPECT().UpdateBrowserSessionData((*sql.Tx)(nil), owner, hash, "ciphertext", fixedNow, wantExpiry).Return(true, nil)
			},
			call: func(backend *dbBackend) (time.Time, error) {
				return backend.Update(settingsContext(), id, []byte("ciphertext"), true)
			},
		},
		{
			name: "touch",
			write: func(database *mocks_data.Database) {
				database.EXPECT().TouchBrowserSession((*sql.Tx)(nil), owner, hash, fixedNow, wantExpiry).Return(true, nil)
			},
			call: func(backend *dbBackend) (time.Time, error) {
				return backend.Touch(settingsContext(), id, true)
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			database := mocks_data.NewDatabase(t)
			database.EXPECT().GetBrowserSessionByOwnerAndSessionIdHash((*sql.Tx)(nil), owner, hash, fixedNow).
				Return(&models.BrowserSession{CreatedAt: sql.NullTime{Valid: false}}, nil)
			tc.write(database)

			expiresAt, err := tc.call(testBackend(database, owner))

			require.NoError(t, err)
			assert.Equal(t, wantExpiry, expiresAt)
		})
	}
}

func TestDatabaseBackend_Lifetimes(t *testing.T) {
	t.Run("uses request settings without a read", func(t *testing.T) {
		database := mocks_data.NewDatabase(t)

		idle, maximum, err := testBackend(database, "owner").lifetimes(settingsContext())

		require.NoError(t, err)
		assert.Equal(t, 2*time.Hour, idle)
		assert.Equal(t, 90*time.Minute, maximum)
		database.AssertNotCalled(t, "GetSettingsById", mock.Anything, mock.Anything)
	})

	t.Run("reads settings without a request value", func(t *testing.T) {
		database := mocks_data.NewDatabase(t)
		database.EXPECT().GetSettingsById((*sql.Tx)(nil), int64(1)).Return(testSettings(), nil)

		idle, maximum, err := testBackend(database, "owner").lifetimes(context.Background())

		require.NoError(t, err)
		assert.Equal(t, 2*time.Hour, idle)
		assert.Equal(t, 90*time.Minute, maximum)
	})

	t.Run("missing settings is an error", func(t *testing.T) {
		database := mocks_data.NewDatabase(t)
		database.EXPECT().GetSettingsById((*sql.Tx)(nil), int64(1)).Return(nil, nil)

		_, _, err := testBackend(database, "owner").lifetimes(context.Background())

		require.Error(t, err)
		assert.NotErrorIs(t, err, sessionstore.ErrNotFound)
	})

	t.Run("failed settings read wraps", func(t *testing.T) {
		cause := errors.New("settings failed")
		database := mocks_data.NewDatabase(t)
		database.EXPECT().GetSettingsById((*sql.Tx)(nil), int64(1)).Return(nil, cause)

		_, _, err := testBackend(database, "owner").lifetimes(context.Background())

		requireWrappedCause(t, err, cause)
	})
}

func TestDatabaseBackend_Delete(t *testing.T) {
	const (
		owner = "owner"
		id    = "delete-id"
	)

	t.Run("passes owner and digest", func(t *testing.T) {
		database := mocks_data.NewDatabase(t)
		database.EXPECT().DeleteBrowserSession((*sql.Tx)(nil), owner, hashSessionId(id)).Return(nil)

		require.NoError(t, testBackend(database, owner).Delete(context.Background(), id))
	})

	t.Run("wraps a failure", func(t *testing.T) {
		cause := errors.New("delete failed")
		database := mocks_data.NewDatabase(t)
		database.EXPECT().DeleteBrowserSession((*sql.Tx)(nil), owner, hashSessionId(id)).Return(cause)

		err := testBackend(database, owner).Delete(context.Background(), id)

		requireWrappedCause(t, err, cause)
	})
}

func TestDatabaseBackend_DigestVectorsReachTheDatabase(t *testing.T) {
	for _, tc := range []struct {
		id     string
		digest string
	}{
		{
			id:     "a-known-session-id",
			digest: "8fe71c16e048ac49c3c7dfaa834953d1af7d4903c398c5b23e8c925bf35a3873",
		},
		{
			id:     "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			digest: "a8ae6e6ee929abea3afcfc5258c8ccd6f85273e0d4626d26c7279f3250f77c8e",
		},
	} {
		t.Run(tc.id, func(t *testing.T) {
			database := mocks_data.NewDatabase(t)
			database.EXPECT().GetBrowserSessionByOwnerAndSessionIdHash((*sql.Tx)(nil), "owner", tc.digest, fixedNow).
				Return(nil, nil)

			_, err := testBackend(database, "owner").Load(context.Background(), tc.id)

			assert.ErrorIs(t, err, sessionstore.ErrNotFound)
		})
	}
}

func TestDatabaseBackend_OnlyDigestsReachStringArguments(t *testing.T) {
	const (
		owner  = "owner"
		id     = "a-known-session-id"
		digest = "8fe71c16e048ac49c3c7dfaa834953d1af7d4903c398c5b23e8c925bf35a3873"
	)

	t.Run("load", func(t *testing.T) {
		database := mocks_data.NewDatabase(t)
		database.EXPECT().GetBrowserSessionByOwnerAndSessionIdHash((*sql.Tx)(nil), owner, digest, fixedNow).Return(nil, nil)
		_, _ = testBackend(database, owner).Load(context.Background(), id)
	})
	t.Run("update", func(t *testing.T) {
		database := mocks_data.NewDatabase(t)
		database.EXPECT().UpdateBrowserSessionData((*sql.Tx)(nil), owner, digest, "data", fixedNow,
			fixedNow.Add(sessionstore.PreAuthLifetime)).Return(true, nil)
		_, _ = testBackend(database, owner).Update(context.Background(), id, []byte("data"), false)
	})
	t.Run("touch", func(t *testing.T) {
		database := mocks_data.NewDatabase(t)
		database.EXPECT().TouchBrowserSession((*sql.Tx)(nil), owner, digest, fixedNow,
			fixedNow.Add(sessionstore.PreAuthLifetime)).Return(true, nil)
		_, _ = testBackend(database, owner).Touch(context.Background(), id, false)
	})
	t.Run("delete", func(t *testing.T) {
		database := mocks_data.NewDatabase(t)
		database.EXPECT().DeleteBrowserSession((*sql.Tx)(nil), owner, digest).Return(nil)
		_ = testBackend(database, owner).Delete(context.Background(), id)
	})
	t.Run("create carries the digest in the model", func(t *testing.T) {
		database := mocks_data.NewDatabase(t)
		database.EXPECT().CreateBrowserSession((*sql.Tx)(nil), mock.MatchedBy(func(row *models.BrowserSession) bool {
			return row.SessionId == id && row.SessionIdHash == digest
		})).Return(nil)
		_, _ = testBackend(database, owner).Create(settingsContext(), id, []byte("data"), false)
	})
}

func TestDatabaseBackend_ConstructorsFixEveryOperationOwner(t *testing.T) {
	for _, tc := range []struct {
		name  string
		owner string
		new   func(database *mocks_data.Database) sessionstore.Backend
	}{
		{
			name:  "auth server",
			owner: constants.AuthServerSessionName,
			new:   func(database *mocks_data.Database) sessionstore.Backend { return NewAuthServerBackend(database) },
		},
		{
			name:  "admin console",
			owner: coreconstants.AdminConsoleSessionName,
			new:   func(database *mocks_data.Database) sessionstore.Backend { return NewAdminConsoleBackend(database) },
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Run("load", func(t *testing.T) {
				database := mocks_data.NewDatabase(t)
				database.EXPECT().GetBrowserSessionByOwnerAndSessionIdHash((*sql.Tx)(nil), tc.owner, mock.Anything, mock.Anything).Return(nil, nil)
				_, _ = tc.new(database).Load(context.Background(), "id")
			})
			t.Run("create", func(t *testing.T) {
				database := mocks_data.NewDatabase(t)
				database.EXPECT().CreateBrowserSession((*sql.Tx)(nil), mock.MatchedBy(func(row *models.BrowserSession) bool {
					return row.Owner == tc.owner
				})).Return(nil)
				_, _ = tc.new(database).Create(settingsContext(), "id", []byte("data"), false)
			})
			t.Run("update", func(t *testing.T) {
				database := mocks_data.NewDatabase(t)
				database.EXPECT().UpdateBrowserSessionData((*sql.Tx)(nil), tc.owner, mock.Anything, "data", mock.Anything, mock.Anything).Return(true, nil)
				_, _ = tc.new(database).Update(context.Background(), "id", []byte("data"), false)
			})
			t.Run("touch", func(t *testing.T) {
				database := mocks_data.NewDatabase(t)
				database.EXPECT().TouchBrowserSession((*sql.Tx)(nil), tc.owner, mock.Anything, mock.Anything, mock.Anything).Return(true, nil)
				_, _ = tc.new(database).Touch(context.Background(), "id", false)
			})
			t.Run("delete", func(t *testing.T) {
				database := mocks_data.NewDatabase(t)
				database.EXPECT().DeleteBrowserSession((*sql.Tx)(nil), tc.owner, mock.Anything).Return(nil)
				_ = tc.new(database).Delete(context.Background(), "id")
			})
		})
	}
}
