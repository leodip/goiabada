package handlers

import (
	"database/sql"
	"testing"

	mocks_data "github.com/leodip/goiabada/authserver/internal/data/mocks"
	"github.com/leodip/goiabada/authserver/internal/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// The four test helpers the handler tests here reach for when the code under test revokes
// something. All four were declared in revocation_test.go and were package-private to this
// package until #387 moved that file to internal/revocation, which is one package away and
// cannot export a test helper to it.
//
// Three are copies, and the fourth, stubRevocationSweepTx, moved whole because revocation_test.go
// never used it: its doc comment already said it is the shape a HANDLER test wants. Copying is
// the answer the tree already gives to this shape -- run_in_transaction_stub_test.go exists in
// five packages, and apihandlers keeps its own assertNotAttemptedOnClientDatabase and callIndex
// beside the one file that calls them -- and sharing them instead is a change of its own, because
// the copies have already diverged.

// revokeTx is an opaque non-nil transaction. revocation.RevokeUserAuthState requires one, so
// passing nil here would exercise a shape production never runs. The mocks never dereference it;
// it only has to be the same pointer the helper forwards.
var revokeTx = &sql.Tx{}

// assertNotAttempted fails if any of the named methods appears in the mock's recorded calls. The
// strict mock would already reject an unexpected call; this states which writes each failure path
// must not have reached, so the intent survives a later edit to the expectations.
func assertNotAttempted(t *testing.T, db *mocks_data.Database, methods ...string) {
	t.Helper()
	for _, call := range db.Calls {
		for _, method := range methods {
			assert.NotEqual(t, method, call.Method, "%v must not be attempted on this path", method)
		}
	}
}

// methodOrder is the sequence of database methods a call issued. Most assertions are about WHAT a
// function wrote; the ones that take this are about WHEN, so the order is what has to be pinned,
// and testify records it whether or not the expectations were registered in that order.
func methodOrder(db *mocks_data.Database) []string {
	order := make([]string, 0, len(db.Calls))
	for _, call := range db.Calls {
		order = append(order, call.Method)
	}
	return order
}

// stubRevocationSweepTx registers every database call revocation.RevokeUserAuthStateTx makes for
// a user with no live sessions and no refresh tokens, which is the shape a handler test wants: it
// exercises the wiring without restating the sweep table revocation_test.go owns exhaustively.
//
// Note it stubs RollbackTransaction as well as CommitTransaction. The deferred rollback runs on
// the success path too, where it is a no-op against a committed transaction, and a test that
// omits it fails on the strict mock.
//
// It also proves the transaction is real: BeginTransaction returns a non-nil tx, so every
// nested call is asserted to receive that exact pointer. A nil one would be rejected by
// revocation.RevokeUserAuthState's precondition.
func stubRevocationSweepTx(database *mocks_data.Database, userId int64, newGeneration int64) {
	expectRunInTransaction(database, revokeTx)
	database.On("IncrementUserAuthStateGeneration", mock.Anything, revokeTx, userId).
		Return(newGeneration, nil).Once()
	database.On("GetRefreshTokensByUserId", mock.Anything, revokeTx, userId).
		Return([]*models.RefreshToken{}, nil).Once()
	database.On("PromoteRefreshTokenGenerations", mock.Anything, revokeTx, []int64{}, newGeneration).
		Return(nil).Once()
	database.On("GetUserSessionsByUserId", mock.Anything, revokeTx, userId).
		Return([]models.UserSession{}, nil).Once()
}
