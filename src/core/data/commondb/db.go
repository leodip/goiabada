package commondb

import (
	"database/sql"
	"fmt"
	"log/slog"
	"time"

	"github.com/huandu/go-sqlbuilder"
	"github.com/leodip/goiabada/core/errs"
)

type CommonDatabase struct {
	DB     *sql.DB
	Flavor sqlbuilder.Flavor
	logSQL bool

	// IsDeadlock reports whether an error is the engine aborting a transaction as a deadlock
	// victim, which is the one class of failure RunInTransaction reruns. Each dialect sets it
	// in its constructor, because only the driver knows its own error type: SQLSTATE 40P01 on
	// PostgreSQL, error 1213 on MySQL, error 1205 on SQL Server. Left nil, nothing is a
	// deadlock and every failure is returned on the first attempt, which is what a handle
	// built directly on this type gets by default rather than by remembering to opt out (#301).
	IsDeadlock func(error) bool
}

func NewCommonDatabase(db *sql.DB, flavor sqlbuilder.Flavor, logSQL bool) *CommonDatabase {
	return &CommonDatabase{
		DB:     db,
		Flavor: flavor,
		logSQL: logSQL,
	}
}

func (d *CommonDatabase) BeginTransaction() (*sql.Tx, error) {
	if d.logSQL {
		slog.Info("beginning transaction")
	}

	tx, err := d.DB.Begin()
	if err != nil {
		return nil, errs.Wrap(err, "unable to begin transaction")
	}
	return tx, nil
}

func (d *CommonDatabase) CommitTransaction(tx *sql.Tx) error {
	if d.logSQL {
		slog.Info("committing transaction")
	}

	err := tx.Commit()
	if err != nil {
		return errs.Wrap(err, "unable to commit transaction")
	}
	return nil
}

func (d *CommonDatabase) RollbackTransaction(tx *sql.Tx) error {
	if d.logSQL {
		slog.Info("rolling back transaction")
	}

	err := tx.Rollback()
	if err != nil {
		return errs.Wrap(err, "unable to rollback transaction")
	}
	return nil
}

// runInTransactionBackoff is the pause before the second and third attempt. Nothing precedes the
// first. Short, because a deadlock victim was rolled back the instant the engine found the cycle
// and the survivor is already past the rows it wanted; the pause only lets the survivor commit.
var runInTransactionBackoff = [...]time.Duration{25 * time.Millisecond, 100 * time.Millisecond}

// sleep is the pause between attempts, a seam so a test can record the durations REQUESTED
// rather than time the wall clock, where a scheduler stall longer than the gap between the two
// values reverses the comparison on a correct helper.
var sleep = time.Sleep

// RunInTransaction opens a transaction, runs fn on it, and commits when fn returns nil or
// rolls back when it does not. Every transaction owner in the repository opens its transaction
// through this, and never through a bare BeginTransaction, because this is where a deadlock is
// answered (#301).
//
// THE RULE. When the engine aborts the transaction as a deadlock victim, from inside fn or at
// the commit, the whole body is rerun, up to three attempts with a short pause before the
// second and third, and only the last such error surfaces, wrapped. Nothing else is rerun: any
// other error fn returns, or any other commit failure, is returned unchanged after one attempt.
// A commit that fails for a reason other than a deadlock has an outcome the client cannot know,
// since the server may have committed before the failure reached it, and replaying it would
// apply the body twice.
//
// WHY IT HOLDS. No order in which transactions take their rows is imposed anywhere in the
// repository, so two transactions on the same account can take the same rows in opposite orders
// and one of them is aborted. The engine
// rolls the victim back with nothing half applied, and every body written for this helper keeps
// its effects inside the transaction and writes its audit event after the commit, so running it
// again is running it for the first time. Lock-wait timeouts are not deadlocks: MySQL 1205 and
// PostgreSQL 55P03 mean a row is HELD, not that a cycle was broken, and rerunning would wait the
// same timeout again. SQLite runs on one connection and cannot deadlock.
//
// WHAT BREAKS IF THIS IS UNDONE. A body that keeps state outside the closure and appends to it
// sees the rolled-back attempt's rows on top of its own; a body that writes its audit event
// inside the transaction records an action a rollback undid. Both are the caller's to avoid, and
// disableAndRevoke is the worked example of the first.
//
// Rollback failures on the error path are logged and never returned: MySQL has already rolled a
// deadlock victim back server-side and says so, and returning that would replace the error the
// caller needs with a bookkeeping one.
func (d *CommonDatabase) RunInTransaction(fn func(tx *sql.Tx) error) error {
	const attempts = 3

	var lastDeadlock error
	for attempt := 1; attempt <= attempts; attempt++ {
		if attempt > 1 {
			sleep(runInTransactionBackoff[attempt-2])
			slog.Warn("rerunning a transaction the engine aborted as a deadlock victim",
				"attempt", attempt, "error", lastDeadlock)
		}

		err := d.runTransactionOnce(fn)
		if err == nil {
			return nil
		}
		if !d.deadlock(err) {
			return err
		}
		lastDeadlock = err
	}

	return errs.Wrapf(lastDeadlock, "transaction aborted as a deadlock victim on all %d attempts", attempts)
}

// runTransactionOnce is one attempt. Its own function so the rollback is deferred, which is
// what makes a panicking fn leave no open transaction behind: the connection goes back to the
// pool clean instead of holding its locks until the pool closes it.
func (d *CommonDatabase) runTransactionOnce(fn func(tx *sql.Tx) error) error {
	tx, err := d.BeginTransaction()
	if err != nil {
		return err
	}

	// Once Commit has been attempted the transaction is finished whatever it answered, and
	// database/sql refuses a Rollback after it. The deferred rollback therefore covers exactly
	// the two exits before the commit: fn returning an error and fn panicking.
	committing := false
	defer func() {
		if committing {
			return
		}
		if rollbackErr := d.RollbackTransaction(tx); rollbackErr != nil {
			slog.Warn("rolling back a failed transaction reported an error, which is ignored because the transaction's own error is the one the caller needs",
				"error", rollbackErr)
		}
	}()

	if err := fn(tx); err != nil {
		return err
	}

	committing = true
	return d.CommitTransaction(tx)
}

// deadlock consults the dialect's classifier, treating none as "nothing is a deadlock".
func (d *CommonDatabase) deadlock(err error) bool {
	return d.IsDeadlock != nil && d.IsDeadlock(err)
}

// inTransaction runs fn inside a transaction: the caller's when one was supplied,
// otherwise one of its own that it commits or rolls back. It lets a method that
// needs several statements be atomic without forcing every caller to open a
// transaction, and without silently splitting the work when they didn't.
//
// Only the nil half retries: handed no transaction this method is the owner and goes
// through RunInTransaction, so a deadlock reruns fn; handed one, it is a nested callee
// and returns the error to the owner, whose rerun covers the whole body rather than
// this piece of it.
func (d *CommonDatabase) inTransaction(tx *sql.Tx, fn func(tx *sql.Tx) error) error {
	if tx != nil {
		return fn(tx)
	}

	return d.RunInTransaction(fn)
}

func (d *CommonDatabase) Log(sql string, args ...any) {
	if d.logSQL {
		slog.Info(fmt.Sprintf("sql: %v", sql))
		argsStr := ""
		for i, arg := range args {
			argsStr += fmt.Sprintf("[arg %v: %v] ", i, arg)
		}
		slog.Info(fmt.Sprintf("sql args: %v", argsStr))
	}
}

func (d *CommonDatabase) ExecSql(tx *sql.Tx, sql string, args ...any) (sql.Result, error) {

	d.Log(sql, args...)

	if tx != nil {
		result, err := tx.Exec(sql, args...)
		if err != nil {
			return nil, errs.Wrap(err, "unable to execute SQL")
		}
		return result, nil
	}

	result, err := d.DB.Exec(sql, args...)
	if err != nil {
		return nil, errs.Wrap(err, "unable to execute SQL")
	}
	return result, nil
}

// QuerySql runs a query and returns its rows.
//
// Callers must check rows.Err() once iteration stops, not only the error returned
// here. A driver is free to report a failure through the result set rather than
// from the query call, and in that case Next() simply returns false. Reading a
// single row then means the caller cannot distinguish "no such row" from "the
// query failed", and every getter here reports a missing row as (nil, nil), so
// without the check a failed read is indistinguishable from a legitimate absence.
// For the getters behind permission and session lookups, that is the wrong
// direction to fail in.
func (d *CommonDatabase) QuerySql(tx *sql.Tx, sql string, args ...any) (*sql.Rows, error) {
	d.Log(sql, args...)

	if tx != nil {
		result, err := tx.Query(sql, args...)
		if err != nil {
			return nil, errs.Wrap(err, "unable to execute SQL")
		}
		return result, nil
	}

	rows, err := d.DB.Query(sql, args...)
	if err != nil {
		return nil, errs.Wrap(err, "unable to execute SQL")
	}
	return rows, nil
}

func (d *CommonDatabase) IsEmpty() (bool, error) {
	settings, err := d.GetSettingsById(nil, 1)
	if err != nil {
		return false, errs.Wrap(err, "failed to check if database is empty")
	}

	return settings == nil, nil
}
