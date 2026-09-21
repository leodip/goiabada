package sessionbackend

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/leodip/goiabada/authserver/internal/constants"
	mocks_data "github.com/leodip/goiabada/authserver/internal/data/mocks"
	"github.com/leodip/goiabada/authserver/internal/models"
	"github.com/leodip/goiabada/core/sessionstore"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// Seam 4 of #386 for the browser-session backend, and thin for the reason section 5 gives.
//
// This backend is the one place where the context was already in the signature and stopped at the
// database call: every method took a ctx from sessionstore and then passed nil-transaction reads
// with no context at all. Stage 6 is what closes that gap, so the claim worth an assertion here is
// that the ctx a method was HANDED is the one its query is issued under -- and the backend sits on
// every request that touches a session, which is what makes the gap worth closing.

type backendCtxKey struct{}

// theCallersContext matches only the context this test handed to the backend, so a query issued
// on a context the backend invented matches nothing and the strict mock reports an unexpected
// call rather than letting the case pass.
func theCallersContext() interface{} {
	return mock.MatchedBy(func(ctx context.Context) bool {
		return ctx.Value(backendCtxKey{}) == "caller"
	})
}

// markedSettingsContext carries both the marker and the settings the backend reads for its
// lifetimes, which is what Create and Touch need before their first write.
func markedSettingsContext() context.Context {
	ctx := context.WithValue(context.Background(), backendCtxKey{}, "caller")
	return context.WithValue(ctx, constants.ContextKeySettings, testSettings())
}

// The accept arm: the read Load makes is issued under the context Load was given.
func TestDatabaseBackend_LoadReadsUnderTheCallersContext(t *testing.T) {
	const owner, id = "owner", "propagation-id"
	database := mocks_data.NewDatabase(t)

	database.On("GetBrowserSessionByOwnerAndSessionIdHash", theCallersContext(), (*sql.Tx)(nil),
		owner, hashSessionId(id), fixedNow).
		Return(&models.BrowserSession{
			Data:          "ciphertext",
			LastAccessed:  fixedNow,
			ExpiresAt:     fixedNow.Add(time.Hour),
			SessionIdHash: hashSessionId(id),
		}, nil).Once()

	record, err := testBackend(database, owner).Load(markedSettingsContext(), id)

	require.NoError(t, err)
	assert.Equal(t, []byte("ciphertext"), record.Data)
	database.AssertExpectations(t)
}

// The write half, in the same shape: Create's insert carries the caller's context too, which is
// the one the /auth/authorize request supplies before it has validated anything.
func TestDatabaseBackend_CreateWritesUnderTheCallersContext(t *testing.T) {
	const owner, id = "owner", "propagation-create"
	database := mocks_data.NewDatabase(t)

	database.On("CreateBrowserSession", theCallersContext(), (*sql.Tx)(nil), mock.Anything).
		Return(nil).Once()

	expires, err := testBackend(database, owner).Create(markedSettingsContext(), id, []byte("data"), false)

	require.NoError(t, err)
	assert.False(t, expires.IsZero())
	database.AssertExpectations(t)
}

// The reject arm: an Update naming a session that is not there reports not found and never
// reaches the insert, so no second port is consulted and there is no context to get wrong.
// Without it the two accept arms would also pass on a backend that wrote unconditionally.
func TestDatabaseBackend_UpdateOfAnAbsentSessionReachesNoInsert(t *testing.T) {
	const owner, id = "owner", "propagation-absent"
	database := mocks_data.NewDatabase(t)

	database.On("UpdateBrowserSessionData", theCallersContext(), (*sql.Tx)(nil),
		owner, hashSessionId(id), "data", fixedNow, mock.Anything).
		Return(false, nil).Once()

	_, err := testBackend(database, owner).Update(markedSettingsContext(), id, []byte("data"), false)

	assert.ErrorIs(t, err, sessionstore.ErrNotFound)
	database.AssertNotCalled(t, "CreateBrowserSession", mock.Anything, mock.Anything, mock.Anything)
	database.AssertNotCalled(t, "TouchBrowserSession", mock.Anything, mock.Anything, mock.Anything,
		mock.Anything, mock.Anything, mock.Anything)
}
