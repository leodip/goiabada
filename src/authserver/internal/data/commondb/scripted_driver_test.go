package commondb

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/huandu/go-sqlbuilder"
	"github.com/leodip/goiabada/core/testutil"
	"github.com/stretchr/testify/assert"
)

// The scripted driver: a database/sql driver that answers every query with the rows it was given
// and every statement with the outcome it was given, records what it saw, and knows nothing about
// SQL. It is this package's way of asking for a failure no real engine can be asked to produce on
// demand.
//
// It arrived with commondb.BackfillLowercaseEmails, whose fail-closed tests needed it, and it
// outlived that pass: #351 replaced the backfill with migration 000047 and a startup pre-flight,
// and RunInTransaction's contract tests (run_in_transaction_test.go) still need exactly this. So
// it lives in a file of its own now rather than inside one caller's tests.
//
// WHY A DRIVER, stated once here because it is the reason to keep it. A result set that yields
// two rows and then dies is what a dropped connection or a server-side timeout looks like part
// way through a scan, and it is the exit whose absence is invisible: sql.Rows reports it through
// Err() after Next() returns false, so a reader that forgets to check sees a TRUNCATED table and
// reports success over a fraction of the rows. Transaction enlistment is invisible from the other
// direction: the successful path's final row state is identical whether the writes were in one
// transaction or five, so only the connection they arrived on distinguishes them. And a
// concurrent write landing exactly between a read and the write that depends on it is not
// something a real engine can be timed into producing reliably.
//
// Where a test needs to know WHICH row a statement addressed it reads the recorded ARGUMENTS
// rather than the query text, so nothing here breaks when a clause is rewritten.

// scriptedDriver answers every query with rows and every exec with an outcome, in the order the
// pass makes them, and records what it saw.
type scriptedDriver struct {
	mu sync.Mutex

	// rows is consumed one entry per query, in order. Running past the end answers with an
	// empty result set rather than failing, so a test only has to script the calls it cares
	// about.
	rows []*scriptedRows
	// execs is consumed one entry per statement, in order, and running past the end answers
	// "one row changed". Per statement rather than one answer for all of them, because the
	// failures worth pinning are at specific points in a sequence of up to five writes, and
	// because reporting NO row changed is how a compare-and-set says it lost a race.
	execs []*scriptedExec

	queryCount int
	execCount  int
	// execArgs is every statement's arguments, in order, which is how a test asserts which row
	// a compare-and-set addressed without reading the query text.
	execArgs [][]driver.Value
	// statements is every statement's TEXT, queries and execs interleaved in the order they
	// reached the connection. The tests above deliberately read arguments rather than text, so
	// that a rewritten clause breaks nothing; a test about the ORDER of statements against
	// different tables has no such option, since the table a statement addresses is in its text
	// and nowhere else (#139).
	statements []string

	openTx int
	// txOptions is every transaction's options as they reached the driver, which is how a test
	// says the isolation level is still the default one: commondb opens with BeginTx(ctx, nil)
	// and nothing in the repository asks for an isolation level.
	txOptions []driver.TxOptions
	// commits counts every Commit the driver was asked for, including the ones commitErrs
	// scripted to fail; rollbacks likewise. A commit that fails is still a commit that was
	// attempted, and RunInTransaction's contract is about how many times it asked.
	commits   int
	rollbacks int
	// commitErrs is consumed one entry per Commit, in order, and running past the end commits
	// cleanly. It exists for RunInTransaction's commit branch: every callback failure leaves
	// the commit untested, and a helper that returned each commit error immediately would pass
	// every callback case while never retrying the one deadlock that surfaces at COMMIT (#301).
	commitErrs []error
	// rollbackErrs is consumed one entry per Rollback, in order. It is how a test plays MySQL's
	// already-rolled-back deadlock victim, whose ROLLBACK the server answers with an error
	// because it has nothing left to roll back.
	rollbackErrs []error
	// escaped counts statements that arrived on a connection with no transaction open on it
	// while a transaction was open on another. That is precisely what passing nil instead of
	// tx looks like from down here: database/sql cannot reuse the connection the transaction
	// holds, so it opens a second one and the statement lands outside the transaction. It is
	// the only signal that distinguishes an enlisted write from an unenlisted one.
	escaped int
}

// scriptedExec is one statement's answer: how many rows it changed, or the failure it met, and
// optionally the id the engine says it generated.
//
// lastInsertId is opt-in, and the default is the one that matters: with it unset the statement
// answers with driver.RowsAffected, whose LastInsertId returns an error. That is pgx's and
// go-mssqldb's behaviour, so a test gets the REFUSING driver unless it asks for the other one,
// which is the right way round for the arm of insertReturningId that reads an id that way (#283,
// #416).
type scriptedExec struct {
	rowsAffected int64
	lastInsertId int64
	err          error
	// delay is how long the engine spends inside this statement before answering, and it is
	// interruptible: the wait is a select on the call's context, so a deadline landing inside
	// the statement is reported as the context's error and not slept through. It is the only
	// way this seam can observe a cancellation that arrives mid-call, and it works only because
	// the driver implements StmtExecContext -- see the context interfaces below (#386).
	delay time.Duration
}

// scriptedResult is what a statement answers once it has an id to report. driver.RowsAffected
// cannot carry one: its LastInsertId is defined to fail.
type scriptedResult struct {
	rowsAffected int64
	lastInsertId int64
}

func (r scriptedResult) LastInsertId() (int64, error) { return r.lastInsertId, nil }
func (r scriptedResult) RowsAffected() (int64, error) { return r.rowsAffected, nil }

func (d *scriptedDriver) Connect(context.Context) (driver.Conn, error) {
	return &scriptedConn{d: d}, nil
}
func (d *scriptedDriver) Driver() driver.Driver            { return d }
func (d *scriptedDriver) Open(string) (driver.Conn, error) { return &scriptedConn{d: d}, nil }

type scriptedConn struct {
	d    *scriptedDriver
	inTx bool
}

func (c *scriptedConn) Prepare(query string) (driver.Stmt, error) {
	return &scriptedStmt{c: c, query: query}, nil
}
func (c *scriptedConn) Close() error { return nil }

func (c *scriptedConn) Begin() (driver.Tx, error) {
	c.d.mu.Lock()
	defer c.d.mu.Unlock()
	c.inTx = true
	c.d.openTx++
	return &scriptedTx{c: c}, nil
}

// THE THREE CONTEXT INTERFACES, and why a legacy driver is not enough.
//
// database/sql refuses an ALREADY cancelled context before it touches the driver, whatever the
// driver implements. What it cannot do for a driver implementing only Conn.Begin, Stmt.Exec and
// Stmt.Query is interrupt a call already in progress: probe/driverfallback measured a 100ms
// deadline against a 700ms legacy Exec returning after 700ms with a NIL error. Every case in
// run_in_transaction_test.go about a cancellation arriving mid-call would therefore pass on a
// helper that ignored the context entirely.
//
// So the driver implements driver.ConnBeginTx, driver.StmtExecContext and driver.StmtQueryContext,
// each honouring the context around the answer it was scripted. The legacy methods stay and share
// the same core, because they are still what a Conn without a transaction reaches in some
// database/sql paths and nothing about their behaviour moves (#386).

func (c *scriptedConn) BeginTx(ctx context.Context, opts driver.TxOptions) (driver.Tx, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	c.d.mu.Lock()
	defer c.d.mu.Unlock()
	c.d.txOptions = append(c.d.txOptions, opts)
	c.inTx = true
	c.d.openTx++
	return &scriptedTx{c: c}, nil
}

type scriptedTx struct{ c *scriptedConn }

func (t *scriptedTx) Commit() error {
	t.c.d.mu.Lock()
	defer t.c.d.mu.Unlock()
	t.c.inTx = false
	t.c.d.openTx--
	t.c.d.commits++
	return popScriptedErr(&t.c.d.commitErrs)
}

func (t *scriptedTx) Rollback() error {
	t.c.d.mu.Lock()
	defer t.c.d.mu.Unlock()
	t.c.inTx = false
	t.c.d.openTx--
	t.c.d.rollbacks++
	return popScriptedErr(&t.c.d.rollbackErrs)
}

// popScriptedErr takes the next scripted outcome off a queue, nil once it is empty. Caller
// holds the driver's mutex.
func popScriptedErr(queue *[]error) error {
	if len(*queue) == 0 {
		return nil
	}
	err := (*queue)[0]
	*queue = (*queue)[1:]
	return err
}

type scriptedStmt struct {
	c     *scriptedConn
	query string
}

func (s *scriptedStmt) Close() error  { return nil }
func (s *scriptedStmt) NumInput() int { return -1 }

// noteStatement records a statement that reached the engine outside an open transaction while
// one was open elsewhere. See scriptedDriver.escaped.
func (s *scriptedStmt) noteStatement() {
	s.c.d.mu.Lock()
	defer s.c.d.mu.Unlock()
	if s.c.d.openTx > 0 && !s.c.inTx {
		s.c.d.escaped++
	}
}

func (s *scriptedStmt) Exec(args []driver.Value) (driver.Result, error) {
	return s.exec(context.Background(), args)
}

func (s *scriptedStmt) ExecContext(ctx context.Context, args []driver.NamedValue) (driver.Result, error) {
	return s.exec(ctx, namedToValues(args))
}

func (s *scriptedStmt) exec(ctx context.Context, args []driver.Value) (driver.Result, error) {
	s.noteStatement()

	d := s.c.d
	d.mu.Lock()
	i := d.execCount
	d.execCount++
	d.execArgs = append(d.execArgs, args)
	d.statements = append(d.statements, s.query)
	var scripted *scriptedExec
	if i < len(d.execs) {
		scripted = d.execs[i]
	}
	d.mu.Unlock()

	if scripted == nil {
		return driver.RowsAffected(1), nil
	}
	if err := spendInsideTheCall(ctx, scripted.delay); err != nil {
		return nil, err
	}
	if scripted.err != nil {
		return nil, scripted.err
	}
	if scripted.lastInsertId != 0 {
		return scriptedResult{rowsAffected: scripted.rowsAffected, lastInsertId: scripted.lastInsertId}, nil
	}
	return driver.RowsAffected(scripted.rowsAffected), nil
}

func (s *scriptedStmt) Query(args []driver.Value) (driver.Rows, error) {
	return s.runQuery(context.Background(), args)
}

func (s *scriptedStmt) QueryContext(ctx context.Context, args []driver.NamedValue) (driver.Rows, error) {
	return s.runQuery(ctx, namedToValues(args))
}

func (s *scriptedStmt) runQuery(ctx context.Context, _ []driver.Value) (driver.Rows, error) {
	s.noteStatement()

	d := s.c.d
	d.mu.Lock()
	i := d.queryCount
	d.queryCount++
	d.statements = append(d.statements, s.query)
	var scripted *scriptedRows
	if i < len(d.rows) {
		scripted = d.rows[i]
	}
	d.mu.Unlock()

	if scripted == nil {
		return &scriptedRows{}, nil
	}
	r := *scripted
	if err := spendInsideTheCall(ctx, r.delay); err != nil {
		return nil, err
	}
	if r.openErr != nil {
		return nil, r.openErr
	}
	return &r, nil
}

// spendInsideTheCall is the engine taking d to answer, interruptibly. A zero delay answers at
// once, which is every case that is not about cancellation.
func spendInsideTheCall(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return ctx.Err()
	}
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

// namedToValues drops the names database/sql attaches, because nothing here binds by name and
// execArgs has always been a positional list.
func namedToValues(args []driver.NamedValue) []driver.Value {
	values := make([]driver.Value, len(args))
	for i, a := range args {
		values[i] = a.Value
	}
	return values
}

// scriptedRows yields values and then either ends or fails. failAt counts rows emitted
// before the failure, so 0 fails immediately and 2 fails after two good rows, which is the
// shape that separates "the query failed" from "the scan stopped half way".
type scriptedRows struct {
	// cols is the column list this result set reports. Empty means the three the backfill's
	// own group read selects, which is the common case in this file. It has to be settable
	// because the pass also reads a two-column scan and a one-column generation read-back, and
	// database/sql refuses a Scan whose destination count differs from it.
	cols   []string
	values [][]driver.Value
	failAt int
	err    error
	// openErr fails the query itself rather than its iteration, which is the difference
	// between a statement the engine refused and a result set that died being read.
	openErr error
	// delay is how long the engine spends before the result set exists, interruptible on the
	// query's context. See scriptedExec.delay.
	delay    time.Duration
	returned int
}

func (r *scriptedRows) Columns() []string {
	if len(r.cols) > 0 {
		return r.cols
	}
	return []string{"id", "email", "enabled"}
}
func (r *scriptedRows) Close() error { return nil }

func (r *scriptedRows) Next(dest []driver.Value) error {
	if r.err != nil && r.returned == r.failAt {
		return r.err
	}
	if r.returned >= len(r.values) {
		return io.EOF
	}
	copy(dest, r.values[r.returned])
	r.returned++
	return nil
}

// scriptedDB wraps a script in the type BackfillLowercaseEmails is a method on. The flavor is
// SQLite because the pass builds one statement for every engine and the flavor only decides the
// placeholder, which this driver ignores.
func scriptedDB(t *testing.T, d *scriptedDriver) *CommonDatabase {
	t.Helper()
	db := sql.OpenDB(d)
	t.Cleanup(func() { _ = db.Close() })
	t.Cleanup(func() { assertNothingEscapedItsTransaction(t, d) })
	return NewCommonDatabase(db, sqlbuilder.SQLite, false)
}

// assertNothingEscapedItsTransaction holds every test in this file to the enlistment property,
// because it costs nothing to check and the write it protects is the one whose absence is
// invisible: a revocation that committed separately from the disable leaves a row that looks
// dealt with holding live credentials at a generation the user still matches.
func assertNothingEscapedItsTransaction(t *testing.T, d *scriptedDriver) {
	t.Helper()
	d.mu.Lock()
	defer d.mu.Unlock()
	assert.Zerof(t, d.escaped,
		"%d statement(s) reached the database on a connection outside the open transaction; every write disableAndRevoke issues must take the tx it was handed", d.escaped)
}

// messagesAt returns the messages logged at one level, in order. A slog record is the only
// observable some branches have -- a target that is a slog.Info call and nothing else stays green
// under a mutation that removes it -- so testutil.CaptureSlog plus this is how such a branch is
// asserted rather than assumed.
func messagesAt(logs *testutil.SlogCapture, level slog.Level) []string {
	out := []string{}
	for _, record := range logs.Records() {
		if record.Level == level {
			out = append(out, record.Message)
		}
	}
	return out
}
