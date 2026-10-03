//go:build !production

// Package datamocks is the test double of data.Database: the mock mockery generates from the
// interface, which every narrow port above the data layer is tested through, and the one
// hand-written stub beside it, ExpectRunInTransaction and its siblings, which answer
// RunInTransaction. Every caller that stubs a transaction already imports this package for the
// mock, so the stub lives here rather than in a package of its own or in a file a binary ships.
// The stub hands the body the transaction the test names and refuses a nil one, so a write moved
// outside the transaction fails the test that expected it inside.
//
// Only the generated file carries mockery's "Code generated ... DO NOT EDIT" marker, so the
// mockery pin guard, which keys on that marker rather than on a filename, leaves the stub alone
// (#338). Every file here carries the generated mock's build tag, for its reason: production builds
// set the production tag, testify is not in them, and a file naming *Database has to be excluded
// exactly where *Database is.
package datamocks

import (
	"context"
	"database/sql"

	"github.com/stretchr/testify/mock"
)

// nilTxPanic is what a nil transaction is refused with, named so the test that pins the refusal
// asserts the message rather than merely that something panicked.
const nilTxPanic = "datamocks: ExpectRunInTransaction needs a non-nil *sql.Tx. A nil one is what " +
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

// ExpectRunInTransactionRerun is the deadlock shape: the body runs, the engine aborts that attempt
// as a deadlock victim -- noted as "rollback" whatever the body returned -- and the helper runs the
// body again, whose outcome is then the helper's, as ExpectRunInTransaction's is. BodyErr is the
// second attempt's.
//
// It exists for a body that collects something as it goes and hands it out after the commit: the
// real RunInTransaction reruns the whole body after an abort, so what the first attempt collected
// never committed, and a body that let it leak into the result would report work the database
// undid. No other shape here runs a body twice, so without this that property had no test.
func ExpectRunInTransactionRerun(db *Database, tx *sql.Tx, note ...func(string)) *RunInTransactionStub {
	if tx == nil {
		panic(nilTxPanic)
	}
	stub := &RunInTransactionStub{}
	db.EXPECT().RunInTransaction(mock.Anything, mock.Anything).RunAndReturn(func(_ context.Context, fn func(tx *sql.Tx) error) error {
		for _, n := range note {
			n("begin")
		}
		_ = fn(tx)
		for _, n := range note {
			n("rollback")
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
		return nil
	}).Once()
	return stub
}

// ExpectRunInTransactionRefused is the shape where the helper cannot open a transaction at all:
// the body never runs and the helper's error is what the caller sees.
func ExpectRunInTransactionRefused(db *Database, err error) {
	db.EXPECT().RunInTransaction(mock.Anything, mock.Anything).Return(err).Once()
}
