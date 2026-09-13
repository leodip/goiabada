package user

import (
	"database/sql"

	mocks_data "github.com/leodip/goiabada/core/data/mocks"
	"github.com/stretchr/testify/mock"
)

// runInTransactionStub is what the mock database answers RunInTransaction with in this package.
// It hands the body the transaction and returns what the body returned, which is the helper's
// behaviour on a body that does not deadlock. The commit on nil and the rollback on an error are
// the real helper's and never reach the mock, so a test that used to assert "nothing committed"
// asserts instead that the body handed its error to the helper, through bodyErr: that is the
// same property observed one layer up, since the helper rolls back exactly when the body errs.
type runInTransactionStub struct {
	// bodyErr is what the body returned, nil when it asked to commit.
	bodyErr error
}

// expectRunInTransaction registers one RunInTransaction call that runs the body on tx and
// returns its error. Every session-manager test in this package hands the body a nil
// transaction, as the BeginTransaction stubs it replaces did: the manager only ever passes it
// back to the database, and the mock does not inspect it.
func expectRunInTransaction(db *mocks_data.Database, tx *sql.Tx) *runInTransactionStub {
	return expectRunInTransactionThenFail(db, tx, nil)
}

// expectRunInTransactionThenFail is the commit-failure shape: the body runs and returns nil,
// and the helper then reports commitErr, as it does when the engine refuses the commit. With a
// nil commitErr it is expectRunInTransaction.
func expectRunInTransactionThenFail(db *mocks_data.Database, tx *sql.Tx, commitErr error) *runInTransactionStub {
	stub := &runInTransactionStub{}
	db.EXPECT().RunInTransaction(mock.Anything).RunAndReturn(func(fn func(tx *sql.Tx) error) error {
		stub.bodyErr = fn(tx)
		if stub.bodyErr != nil {
			return stub.bodyErr
		}
		return commitErr
	}).Once()
	return stub
}

// expectRunInTransactionRefused is the shape where the helper cannot open a transaction at all:
// the body never runs and the helper's error is what the caller sees.
func expectRunInTransactionRefused(db *mocks_data.Database, err error) {
	db.EXPECT().RunInTransaction(mock.Anything).Return(err).Once()
}
