//go:build !production

package mocks_data

import (
	"context"
	"database/sql"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// stubTx is the sentinel these tests hand the stub, and the shape every caller of the stub is
// told to declare: non-nil, never dereferenced, and identity-compared by the expectations
// written against it.
var stubTx = &sql.Tx{}

// The six per-package copies this file replaced were each covered only by the tests that used
// them, so every property below was one no test stated. It is now one package's job, and these
// are its cases: the transaction the body is handed, the error the body returns, the commit
// that fails after a body that did not, the edges a note sees, the transaction that never
// opens, and the nil this stub refuses.

func TestExpectRunInTransaction_RunsTheBodyOnTheGivenTransaction(t *testing.T) {
	db := NewDatabase(t)
	stub := ExpectRunInTransaction(db, stubTx)

	var seen *sql.Tx
	err := db.RunInTransaction(context.Background(), func(tx *sql.Tx) error {
		seen = tx
		return nil
	})

	require.NoError(t, err, "a body that commits leaves the helper with nothing to report")
	assert.Same(t, stubTx, seen, "the body runs on the transaction the caller named")
	assert.NoError(t, stub.BodyErr, "BodyErr is nil when the body asked to commit")
}

func TestExpectRunInTransaction_HandsTheBodysErrorBackAndRecordsIt(t *testing.T) {
	db := NewDatabase(t)
	stub := ExpectRunInTransaction(db, stubTx)

	boom := errors.New("the write failed")
	err := db.RunInTransaction(context.Background(), func(*sql.Tx) error { return boom })

	assert.ErrorIs(t, err, boom, "the caller sees what the body returned")
	assert.ErrorIs(t, stub.BodyErr, boom,
		"BodyErr is how a test says the helper rolled back, which it does exactly when the body errs")
}

func TestExpectRunInTransactionThenFail_ReportsTheCommitFailureAfterABodyThatDidNotErr(t *testing.T) {
	db := NewDatabase(t)
	commitErr := errors.New("the engine refused the commit")
	stub := ExpectRunInTransactionThenFail(db, stubTx, commitErr)

	ran := false
	err := db.RunInTransaction(context.Background(), func(*sql.Tx) error {
		ran = true
		return nil
	})

	assert.True(t, ran, "the body runs: the commit is what fails, not the transaction")
	assert.ErrorIs(t, err, commitErr, "the caller sees the commit's error")
	assert.NoError(t, stub.BodyErr, "the body committed, so there is no body error to record")
}

func TestExpectRunInTransaction_NotesTheEdgesAroundTheBody(t *testing.T) {
	t.Run("commit", func(t *testing.T) {
		db := NewDatabase(t)
		var edges []string
		ExpectRunInTransaction(db, stubTx, func(edge string) { edges = append(edges, edge) })

		_ = db.RunInTransaction(context.Background(), func(*sql.Tx) error {
			edges = append(edges, "body")
			return nil
		})

		assert.Equal(t, []string{"begin", "body", "commit"}, edges)
	})

	t.Run("rollback", func(t *testing.T) {
		db := NewDatabase(t)
		var edges []string
		ExpectRunInTransaction(db, stubTx, func(edge string) { edges = append(edges, edge) })

		_ = db.RunInTransaction(context.Background(), func(*sql.Tx) error {
			edges = append(edges, "body")
			return errors.New("the write failed")
		})

		assert.Equal(t, []string{"begin", "body", "rollback"}, edges)
	})

	t.Run("a commit failure still closes with commit, because the body did not err", func(t *testing.T) {
		db := NewDatabase(t)
		var edges []string
		ExpectRunInTransactionThenFail(db, stubTx, errors.New("the engine refused the commit"),
			func(edge string) { edges = append(edges, edge) })

		_ = db.RunInTransaction(context.Background(), func(*sql.Tx) error { return nil })

		assert.Equal(t, []string{"begin", "commit"}, edges)
	})
}

func TestExpectRunInTransactionRefused_NeverRunsTheBody(t *testing.T) {
	db := NewDatabase(t)
	beginErr := errors.New("unable to open a transaction")
	ExpectRunInTransactionRefused(db, beginErr)

	ran := false
	err := db.RunInTransaction(context.Background(), func(*sql.Tx) error {
		ran = true
		return nil
	})

	assert.ErrorIs(t, err, beginErr)
	assert.False(t, ran, "the transaction never opened, so nothing inside it ran")
}

// A nil transaction is refused at registration, not at the call, so the test that wrote it is
// the test that fails. This is the property the six copies disagreed about: two declared a
// sentinel and explained why, four took whatever the caller passed, and two call sites passed
// nil -- which matches an expectation written against a call made outside any transaction, so
// a write moved back outside one would have passed on call count alone.
func TestExpectRunInTransaction_RefusesANilTransaction(t *testing.T) {
	db := NewDatabase(t)

	assert.PanicsWithValue(t, nilTxPanic, func() { ExpectRunInTransaction(db, nil) })
	assert.PanicsWithValue(t, nilTxPanic, func() { ExpectRunInTransactionThenFail(db, nil, nil) })
	// A typed nil is the other spelling the merged call sites used, and == nil sees it.
	assert.PanicsWithValue(t, nilTxPanic, func() { ExpectRunInTransaction(db, (*sql.Tx)(nil)) })

	// Nothing was registered by any of the three, which is what lets NewDatabase's cleanup
	// assert expectations without a call to satisfy.
	assert.Empty(t, db.ExpectedCalls)
}

// The stub registers one call and not a standing answer, so a second RunInTransaction is
// unexpected. It is observed on a bare &Database{}, with no testing interface registered:
// there, testify panics on an unmatched call instead of failing the test that is asserting it.
func TestExpectRunInTransaction_RegistersExactlyOneCall(t *testing.T) {
	db := &Database{}
	ExpectRunInTransaction(db, stubTx)

	commit := func(*sql.Tx) error { return nil }
	require.NoError(t, db.RunInTransaction(context.Background(), commit))
	assert.Panics(t, func() { _ = db.RunInTransaction(context.Background(), commit) },
		"the second call matches nothing, so a test expecting one transaction sees two")
}
