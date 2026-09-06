package apihandlers

import (
	"database/sql"

	mocks_data "github.com/leodip/goiabada/core/data/mocks"
	"github.com/stretchr/testify/mock"
)

// runInTransactionStub is what the mock database answers RunInTransaction with in this package.
// It hands the body tx and returns what the body returned, which is the helper's behaviour on a
// body that does not deadlock. The commit on nil and the rollback on an error are the real
// helper's and never reach the mock, so a test that used to assert "nothing committed" asserts
// instead that the body handed its error to the helper, through bodyErr, which is exactly when
// the helper rolls back.
type runInTransactionStub struct {
	bodyErr error
	bodyRan bool
}

// expectRunInTransaction registers one RunInTransaction call that runs the body on tx and
// returns its error.
func expectRunInTransaction(database *mocks_data.Database, tx *sql.Tx) *runInTransactionStub {
	stub := &runInTransactionStub{}
	database.EXPECT().RunInTransaction(mock.Anything).RunAndReturn(func(fn func(tx *sql.Tx) error) error {
		stub.bodyRan = true
		stub.bodyErr = fn(tx)
		return stub.bodyErr
	}).Once()
	return stub
}
