package commondb

import (
	"context"
	"database/sql"
	"errors"
	"log/slog"
	"time"

	"github.com/huandu/go-sqlbuilder"
	"github.com/leodip/goiabada/core/errs"
)

// CommonDatabase is the one implementation of the Database interface, and the four engine
// adapters embed it rather than delegating to it method by method. Each adapter declares only
// the methods its engine needs different SQL for; every other method is promoted from here, so
// a query is written once and a signature changes once (#416).
//
// WHAT EMBEDDING DOES NOT BUY, stated because the shape invites the opposite belief: dynamic
// dispatch. A call this package makes on its own receiver resolves to the implementation below
// at compile time, whatever engine is running, so it never reaches the adapter's override even
// when the override is the only version that works on that engine.
// TestCommonDatabase_NoSelfCallToAnOverriddenMethod refuses that call, and #283 is the one that
// shipped: an audit insert that ended at LastInsertId, which two of the four drivers refuse.
//
// The compiler still holds each adapter to the whole interface, so an engine cannot lose a
// method by omission; what it cannot check is that a method promoted from here is right for
// that engine.
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

	// IsUniqueViolation reports whether an error is the engine refusing a write because a unique
	// index already holds that value. Each dialect sets it in its constructor, because only the
	// driver knows its own error type and its own number: SQLite 2067, MySQL 1062, PostgreSQL
	// SQLSTATE 23505, SQL Server 2627 for a UNIQUE constraint and 2601 for a unique index. Left
	// nil, nothing is a unique violation and every failure surfaces untagged, which is what a
	// handle built directly on this type gets by default rather than by remembering to opt out.
	//
	// WrapSQLError is the only consumer: a classified failure leaves the data layer carrying
	// ErrUniqueViolation, so no caller above it ever sees a driver number or a driver sentence
	// (#279).
	IsUniqueViolation func(error) bool

	// InsertReturningIdSQL rewrites a built INSERT so that the engine reports the new row's id
	// in a result set. Each dialect sets it in its constructor, because only the engine's own
	// grammar says how: PostgreSQL appends RETURNING id, SQL Server splices OUTPUT INSERTED.id
	// in front of VALUES. Left nil, the insert goes through ExecSql and the id is read from
	// LastInsertId, which is what SQLite and MySQL do, and which is what a handle built
	// directly on this type gets by default rather than by remembering to opt out.
	//
	// insertReturningId is the only consumer, and it is the only place the 25 Create* methods
	// obtain an id. Until #416 the two engines whose drivers refuse LastInsertId wrote all 25
	// out by hand: fifty bodies of forty lines, differing in this one expression.
	InsertReturningIdSQL func(insertSQL string) (string, error)
}

func NewCommonDatabase(db *sql.DB, flavor sqlbuilder.Flavor, logSQL bool) *CommonDatabase {
	return &CommonDatabase{
		DB:     db,
		Flavor: flavor,
		logSQL: logSQL,
	}
}

func (d *CommonDatabase) BeginTransaction(ctx context.Context) (*sql.Tx, error) {
	if d.logSQL {
		slog.InfoContext(ctx, "beginning transaction")
	}

	// BeginTx with nil options, which is sql.LevelDefault and read-write: no code in this
	// repository asks for an isolation level, and the context is here so that a caller who has
	// given up stops waiting for a connection the pool has not got. On SQLite, whose pool is
	// one connection, that wait is the whole of #413's self-deadlock (#386).
	tx, err := d.DB.BeginTx(ctx, nil)
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
//
// It takes the context and returns its error because the pause has to be interruptible: a caller
// that is already gone should not be held for another 100ms and then handed a fresh transaction.
// time.Sleep cannot be interrupted, so the wait is a select on ctx.Done(); the seam is still this
// variable, and a test that wants the real wait keeps it.
var sleep = func(ctx context.Context, d time.Duration) error {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

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
func (d *CommonDatabase) RunInTransaction(ctx context.Context, fn func(tx *sql.Tx) error) error {
	const attempts = 3

	var lastDeadlock error
	for attempt := 1; attempt <= attempts; attempt++ {
		if err := ctx.Err(); err != nil {
			return abandoned(err, lastDeadlock)
		}

		if attempt > 1 {
			if err := sleep(ctx, runInTransactionBackoff[attempt-2]); err != nil {
				return abandoned(err, lastDeadlock)
			}
			slog.WarnContext(ctx, "rerunning a transaction the engine aborted as a deadlock victim",
				"attempt", attempt, "error", lastDeadlock)
		}

		err := d.runTransactionOnce(ctx, fn)
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

// abandoned is what a cancelled run returns: the context's error, joined to the deadlock that was
// the reason the helper was about to try again when there was one.
//
// The context error wins because it is the one that decided the outcome -- the caller is gone, and
// nothing below chose that. The deadlock is joined rather than dropped because losing it leaves a
// record saying only "cancelled" for a transaction the engine had been aborting, which is the one
// fact worth keeping. Both stay reachable: errors.Is answers for context.Canceled and
// context.DeadlineExceeded, and errors.Is and errors.As still reach the engine's own abort
// (#386 decision 13).
//
// A cancellation arriving INSIDE fn does not come through here. The statement's own context error
// is not a deadlock, so the loop returns it unchanged after one attempt, which is the same answer
// by the ordinary path.
func abandoned(ctxErr error, lastDeadlock error) error {
	if lastDeadlock != nil {
		return errs.Wrap(errs.Join(ctxErr, lastDeadlock),
			"transaction abandoned after the engine aborted it as a deadlock victim")
	}
	return errs.Wrap(ctxErr, "transaction abandoned")
}

// runTransactionOnce is one attempt. Its own function so the rollback is deferred, which is
// what makes a panicking fn leave no open transaction behind: the connection goes back to the
// pool clean instead of holding its locks until the pool closes it.
func (d *CommonDatabase) runTransactionOnce(ctx context.Context, fn func(tx *sql.Tx) error) error {
	tx, err := d.BeginTransaction(ctx)
	if err != nil {
		return err
	}

	// Once Commit has been attempted the transaction is finished whatever it answered, and
	// database/sql refuses a Rollback after it. The deferred rollback therefore covers exactly
	// the two exits before the commit: fn returning an error and fn panicking.
	//
	// A THIRD FINISHED STATE arrives with the context. When ctx is done, database/sql rolls the
	// transaction back on the goroutine it started at BeginTx, so by the time this runs the
	// rollback the caller needed has already happened and tx.Rollback answers sql.ErrTxDone.
	// Nothing failed there, so it earns no record: warning on it would put a line in the log for
	// every cancelled request that was inside a transaction, which is an operator sent after a
	// non-event. Only a rollback that failed for some OTHER reason is still worth the warning,
	// and a live context still reports ErrTxDone as the anomaly it would be (#386).
	committing := false
	defer func() {
		if committing {
			return
		}
		rollbackErr := d.RollbackTransaction(tx)
		if rollbackErr == nil || (ctx.Err() != nil && errors.Is(rollbackErr, sql.ErrTxDone)) {
			return
		}
		slog.WarnContext(ctx, "rolling back a failed transaction reported an error, which is ignored because the transaction's own error is the one the caller needs",
			"error", rollbackErr)
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

// uniqueViolation consults the dialect's classifier, treating none as "nothing is a unique
// violation".
func (d *CommonDatabase) uniqueViolation(err error) bool {
	return d.IsUniqueViolation != nil && d.IsUniqueViolation(err)
}

// WrapSQLError wraps a failure the driver reported with msg, tagging a unique-key violation with
// the ErrUniqueViolation sentinel first. Nil in, nil out.
//
// It is the one place a driver's dialect-specific refusal becomes something the rest of the tree
// can match: above this, a caller asks errors.Is(err, data.ErrUniqueViolation) and never a number,
// a type or a sentence. The driver's own error stays in the tree and is still reachable through
// errors.As, for the rare caller that needs to know which key was violated.
//
// The message on the tagged branch reads "<msg>: unique constraint violation: <driver text>": the
// prefix is the only change to what this layer has always printed. errs.Errorf carries both %w
// verbs, so the sentinel and the driver error are both unwrappable and the tree still holds exactly
// one stack, the origin's, since neither operand brought one.
//
// Exported because two engine packages need it: PostgreSQL and SQL Server insert through
// INSERT ... RETURNING / OUTPUT INSERTED and then re-check rows.Err(), because those drivers can
// defer a constraint violation to the result set rather than returning it from the query. That arm
// lives in their own packages and would otherwise be the one path on which the sentinel never
// appears (#279).
func (d *CommonDatabase) WrapSQLError(err error, msg string) error {
	if err == nil {
		return nil
	}
	if d.uniqueViolation(err) {
		return errs.Wrap(errs.Errorf("%w: %w", ErrUniqueViolation, err), msg)
	}
	return errs.Wrap(err, msg)
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
func (d *CommonDatabase) inTransaction(ctx context.Context, tx *sql.Tx, fn func(tx *sql.Tx) error) error {
	if tx != nil {
		return fn(tx)
	}

	return d.RunInTransaction(ctx, fn)
}

// Log writes one record per statement when GOIABADA_AUTHSERVER_LOG_SQL is on.
//
// It takes no arguments beyond the statement, and that is the point rather than a
// simplification. It used to write a second record listing every bound value, and
// nothing at this layer can tell a password hash, a TOTP seed or an encrypted
// client secret from a page size: every value the product writes to the database
// passes through here. Every other logger in this tree already bounds or redacts
// what it writes (#145, #159), and a flag an operator turns on to see which
// queries run should not be the one path that publishes what they ran with.
// Restore the arguments and the log carries credentials in the clear (#320).
func (d *CommonDatabase) Log(ctx context.Context, sql string) {
	if d.logSQL {
		slog.InfoContext(ctx, "sql", "statement", sql)
	}
}

func (d *CommonDatabase) ExecSql(ctx context.Context, tx *sql.Tx, sql string, args ...any) (sql.Result, error) {

	d.Log(ctx, sql)

	if tx != nil {
		result, err := tx.ExecContext(ctx, sql, args...)
		if err != nil {
			return nil, d.WrapSQLError(err, "unable to execute SQL")
		}
		return result, nil
	}

	result, err := d.DB.ExecContext(ctx, sql, args...)
	if err != nil {
		return nil, d.WrapSQLError(err, "unable to execute SQL")
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
func (d *CommonDatabase) QuerySql(ctx context.Context, tx *sql.Tx, sql string, args ...any) (*sql.Rows, error) {
	d.Log(ctx, sql)

	if tx != nil {
		result, err := tx.QueryContext(ctx, sql, args...)
		if err != nil {
			return nil, d.WrapSQLError(err, "unable to execute SQL")
		}
		return result, nil
	}

	rows, err := d.DB.QueryContext(ctx, sql, args...)
	if err != nil {
		return nil, d.WrapSQLError(err, "unable to execute SQL")
	}
	return rows, nil
}

// insertReturningId runs a built INSERT and returns the id the engine gave the new row. It is
// the one place the four engines differ on how that id comes back, and the only place the 25
// Create* methods obtain one.
//
// noun names the thing being inserted and reaches the two messages this can fail with,
// "unable to insert <noun>" and "unable to scan <noun> id". Both are what each engine's
// hand-written copy printed before they collapsed onto this, so no error text moved (#416).
//
// It takes the builder rather than a built statement so that the Build call, and with it the
// local named sql that shadows the database/sql import, leaves all 25 callers.
//
// THE DEFERRED VIOLATION is why the returning arm ends the way it does. pgx and go-mssqldb can
// both report a constraint violation through the result set rather than from the query call, and
// then Next() simply reports no row. Without the rows.Err() check the insert would read as a
// success with id 0, and data.ErrUniqueViolation -- which the handler above needs to answer 409
// rather than 500 -- would be unreachable on exactly the two engines that take this arm. It goes
// through WrapSQLError rather than errs.Wrap for that reason; the failure QuerySql itself returns
// has already been through WrapSQLError (#279).
func (d *CommonDatabase) insertReturningId(ctx context.Context, tx *sql.Tx,
	insertBuilder *sqlbuilder.InsertBuilder, noun string) (int64, error) {

	statement, args := insertBuilder.Build()

	if d.InsertReturningIdSQL == nil {
		result, err := d.ExecSql(ctx, tx, statement, args...)
		if err != nil {
			return 0, errs.Wrap(err, "unable to insert "+noun)
		}

		id, err := result.LastInsertId()
		if err != nil {
			return 0, errs.Wrap(err, "unable to get last insert id")
		}
		return id, nil
	}

	statement, err := d.InsertReturningIdSQL(statement)
	if err != nil {
		return 0, err
	}

	rows, err := d.QuerySql(ctx, tx, statement, args...)
	if err != nil {
		return 0, errs.Wrap(err, "unable to insert "+noun)
	}
	defer func() { _ = rows.Close() }()

	var id int64
	if rows.Next() {
		if err := rows.Scan(&id); err != nil {
			return 0, errs.Wrap(err, "unable to scan "+noun+" id")
		}
	}

	if err := rows.Err(); err != nil {
		return 0, d.WrapSQLError(err, "unable to insert "+noun)
	}

	return id, nil
}

func (d *CommonDatabase) IsEmpty() (bool, error) {
	settings, err := d.GetSettingsById(nil, 1)
	if err != nil {
		return false, errs.Wrap(err, "failed to check if database is empty")
	}

	return settings == nil, nil
}
