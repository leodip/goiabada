package handlers

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
	// bodyRan reports whether the body was invoked at all.
	bodyRan bool
}

// expectRunInTransaction registers one RunInTransaction call that runs the body on tx and
// returns its error. An optional note is called with "begin" at entry and then with "commit" or
// "rollback" as the helper would, so an ordering test can still show where the transaction's
// edges fall relative to the statements inside it and to what the caller does afterwards.
func expectRunInTransaction(db *mocks_data.Database, tx *sql.Tx, note ...func(string)) *runInTransactionStub {
	return expectRunInTransactionThenFail(db, tx, nil, note...)
}

// expectRunInTransactionThenFail is the commit-failure shape: the body runs and returns nil,
// and the helper then reports commitErr, as it does when the engine refuses the commit. With a
// nil commitErr it is expectRunInTransaction.
func expectRunInTransactionThenFail(db *mocks_data.Database, tx *sql.Tx, commitErr error, note ...func(string)) *runInTransactionStub {
	stub := &runInTransactionStub{}
	db.EXPECT().RunInTransaction(mock.Anything).RunAndReturn(func(fn func(tx *sql.Tx) error) error {
		for _, n := range note {
			n("begin")
		}
		stub.bodyRan = true
		stub.bodyErr = fn(tx)
		if stub.bodyErr != nil {
			for _, n := range note {
				n("rollback")
			}
			return stub.bodyErr
		}
		for _, n := range note {
			n("commit")
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
