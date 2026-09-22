//go:build !production

package mocks_data

import (
	"context"
	"database/sql"

	"github.com/stretchr/testify/mock"
)

// This file is hand-written and sits beside a generated one on purpose.
//
// It is the one stub that answers RunInTransaction on the mock Database, and it lives here
// because here is the only package every caller already reaches: six packages -- handlers,
// apihandlers, revocation, otpcredential, usercreation and usersession -- each carried their
// own ~58-line copy until this replaced them, and all twenty of their test files already
// import this one. The alternative placements each cost an edge that did not exist: a package
// under internal/testutil importing internal/data/mocks, or a non-test file in a package that
// ships. Nothing is generated here, so the mockery pin guard leaves it alone: that guard keys
// on mockery's own "Code generated ... DO NOT EDIT" marker rather than on a filename, which is
// what also leaves core/mocks/test_fs_mock.go, hand-written under the same kind of name, out
// of it (#338).
//
// The build tag is the generated mock's, for the generated mock's reason: production builds
// pass -tags=production and testify is not in them, so a file naming *Database has to be
// excluded exactly where *Database is.

// nilTxPanic is what a nil transaction is refused with, named so the test that pins the refusal
// asserts the message rather than merely that something panicked.
const nilTxPanic = "mocks_data: ExpectRunInTransaction needs a non-nil *sql.Tx. A nil one is what " +
	"a call made outside any transaction passes, so an expectation written against it cannot " +
	"tell a write inside the transaction from one moved back outside it. Declare a sentinel -- " +
	"var someTx = &sql.Tx{} -- and expect that instead."

// RunInTransactionStub records what the body handed back to the helper.
//
// The real RunInTransaction commits when the body returns nil and rolls back when it does not,
// and neither reaches a mock, so a test that wants to say "nothing was committed" says instead
// that the body handed the helper an error, through BodyErr. That is the same property observed
// one layer up, since the helper rolls back exactly when the body errs.
type RunInTransactionStub struct {
	// BodyErr is what the body returned, nil when it asked to commit.
	BodyErr error
}

// ExpectRunInTransaction registers one RunInTransaction call that runs the body on tx and
// returns its error. An optional note is called with "begin" at entry and then with "commit" or
// "rollback" as the helper would, so an ordering test can still show where the transaction's
// edges fall relative to the statements inside it and to what the caller does afterwards.
func ExpectRunInTransaction(db *Database, tx *sql.Tx, note ...func(string)) *RunInTransactionStub {
	return ExpectRunInTransactionThenFail(db, tx, nil, note...)
}

// ExpectRunInTransactionThenFail is the commit-failure shape: the body runs and returns nil,
// and the helper then reports commitErr, as it does when the engine refuses the commit. With a
// nil commitErr it is ExpectRunInTransaction.
//
// tx must not be nil, and that is the rule this file exists to make unescapable rather than a
// convention four of the six copies happened to keep. Every Database method takes the
// transaction it runs under, and a call made outside any transaction passes nil, so a stub that
// hands the body nil makes the two indistinguishable: an expectation written against nil matches
// a write made inside the transaction and a write moved back outside it, and the test passes
// either way. Two call sites passed nil when the six copies were merged, and both were asserting
// through (*sql.Tx)(nil) against a transaction they meant to be inside.
func ExpectRunInTransactionThenFail(db *Database, tx *sql.Tx, commitErr error, note ...func(string)) *RunInTransactionStub {
	if tx == nil {
		panic(nilTxPanic)
	}
	stub := &RunInTransactionStub{}
	db.EXPECT().RunInTransaction(mock.Anything, mock.Anything).RunAndReturn(func(_ context.Context, fn func(tx *sql.Tx) error) error {
		for _, n := range note {
			n("begin")
		}
		stub.BodyErr = fn(tx)
		if stub.BodyErr != nil {
			for _, n := range note {
				n("rollback")
			}
			return stub.BodyErr
		}
		for _, n := range note {
			n("commit")
		}
		return commitErr
	}).Once()
	return stub
}

// ExpectRunInTransactionRefused is the shape where the helper cannot open a transaction at all:
// the body never runs and the helper's error is what the caller sees.
func ExpectRunInTransactionRefused(db *Database, err error) {
	db.EXPECT().RunInTransaction(mock.Anything, mock.Anything).Return(err).Once()
}
