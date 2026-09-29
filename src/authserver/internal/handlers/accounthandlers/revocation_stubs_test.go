package accounthandlers

import (
	"database/sql"

	mocks_data "github.com/leodip/goiabada/authserver/internal/data/mocks"
	"github.com/leodip/goiabada/authserver/internal/models"
	"github.com/stretchr/testify/mock"
)

// The two revocation helpers the password reset tests reach for, which came with them from the
// parent handlers package in #435. stubRevocationSweepTx moved whole, having no other caller;
// revokeTx is a copy, because the parent's token tests still use theirs and a test helper cannot
// be exported across packages. Copying is the answer the tree already gives to this shape, as the
// parent's revocation_stubs_test.go records.

// revokeTx is an opaque non-nil transaction. revocation.RevokeUserAuthState requires one, so
// passing nil here would exercise a shape production never runs. The mocks never dereference it;
// it only has to be the same pointer the helper forwards.
var revokeTx = &sql.Tx{}

// stubRevocationSweepTx registers every database call revocation.RevokeUserAuthStateTx makes for
// a user with no live sessions and no refresh tokens, which is the shape a handler test wants: it
// exercises the wiring without restating the sweep table revocation_test.go owns exhaustively.
//
// It also proves the transaction is real: the helper hands the body a non-nil tx, so every
// nested call is asserted to receive that exact pointer. A nil one would be rejected by
// revocation.RevokeUserAuthState's precondition.
func stubRevocationSweepTx(database *mocks_data.Database, userId int64, newGeneration int64) {
	mocks_data.ExpectRunInTransaction(database, revokeTx)
	database.On("IncrementUserAuthStateGeneration", mock.Anything, revokeTx, userId).
		Return(newGeneration, nil).Once()
	database.On("GetRefreshTokensByUserId", mock.Anything, revokeTx, userId).
		Return([]*models.RefreshToken{}, nil).Once()
	database.On("PromoteRefreshTokenGenerations", mock.Anything, revokeTx, []int64{}, newGeneration).
		Return(nil).Once()
	database.On("GetUserSessionsByUserId", mock.Anything, revokeTx, userId).
		Return([]models.UserSession{}, nil).Once()
}
