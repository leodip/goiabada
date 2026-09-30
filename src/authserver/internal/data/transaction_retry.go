package data

import (
	"context"
	"database/sql"
	"errors"
)

// TransactionRunner is the one method RunInTransactionRetryingConflict needs of a database.
type TransactionRunner interface {
	RunInTransaction(ctx context.Context, fn func(tx *sql.Tx) error) error
}

// RunInTransactionRetryingConflict runs fn in a transaction, and once more when the first attempt
// lost a unique key to a concurrent writer (#437).
//
// A caller that inserts a row only when it is absent reads first and writes second, so two callers
// that overlap can both read absent and the second insert then loses on the key. On PostgreSQL that
// refusal aborts the transaction it ran in, so the loser cannot carry on: it rolls back and runs
// again, and the second attempt reads the row the winner committed and finds it present. The
// attempt is bounded at two because a third collision would mean a writer that keeps creating the
// row this one keeps failing to read, which is a fault and not a race.
//
// fn must be safe to run twice. Every read it needs is inside it, and what it reports to its caller
// is whatever the attempt that committed produced, the rule RunInTransaction states for a
// deadlock's rerun.
func RunInTransactionRetryingConflict(ctx context.Context, db TransactionRunner, fn func(tx *sql.Tx) error) error {
	err := db.RunInTransaction(ctx, fn)
	if errors.Is(err, ErrUniqueViolation) {
		return db.RunInTransaction(ctx, fn)
	}
	return err
}
