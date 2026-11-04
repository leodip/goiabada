package handlers

import (
	"context"
	"database/sql"

	datamocks "github.com/leodip/goiabada/authserver/internal/data/mocks"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/stretchr/testify/mock"
)

// otpWriteTx is the transaction a refused code's count and a recovery code's claim run in, once
// each: the count reads the user's row under the lock its write holds when it disables the
// authenticator, and the claim takes that row first, for the notice's address (#724, #737).
var otpWriteTx = &sql.Tx{}

// expectOTPWriteTransactions lets the step open any number of those transactions, each running its
// body on otpWriteTx. The writes inside keep their own expectations, so a write the case does not
// arm still fails it.
func expectOTPWriteTransactions(database *datamocks.Database) {
	database.EXPECT().RunInTransaction(mock.Anything, mock.Anything).
		RunAndReturn(func(_ context.Context, fn func(tx *sql.Tx) error) error { return fn(otpWriteTx) }).Maybe()
}

// expectUserRowLocked answers the locking read of user's row inside otpWriteTx with held.
func expectUserRowLocked(database *datamocks.Database, held *record.User) {
	database.On("GetUserByIdForUpdate", mock.Anything, otpWriteTx, held.Id).Return(held, nil).Maybe()
}
