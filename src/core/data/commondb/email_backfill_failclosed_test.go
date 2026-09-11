package commondb

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/huandu/go-sqlbuilder"
	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/models"
	"github.com/leodip/goiabada/core/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// This file pins three properties of BackfillLowercaseEmails that no engine can be asked to
// demonstrate on demand, so all three need a scripted driver rather than a database:
//
//  1. Every way storage can fail the pass comes back to the caller as an error.
//  2. Every write disableAndRevoke issues is enlisted in the one transaction it opened, and a
//     failure after the enabled-to-disabled transition rolls the whole of it back.
//  3. The group is re-read immediately before it is decided, and each write is guarded on the
//     address that re-read saw, so a row somebody else changed in between is left alone.
//  4. The revocation's audit event reaches whichever of the two targets the operator's settings
//     name, and reaching the database target does not itself report a failure on a driver that
//     refuses LastInsertId, which is what pgx and go-mssqldb both do.
//
// The rule the pass applies is TestPickEmailSurvivor's, and its four-engine behaviour is the
// data tier's. Neither is retested here.
//
// Why a driver. A result set that yields two rows and then dies is what a dropped connection or
// a server-side timeout looks like part way through a scan, and it is the exit whose absence is
// invisible: sql.Rows reports it through Err() after Next() returns false, so a pass that
// forgets to check reads a TRUNCATED users table, decides it has seen every group, and reports
// success having converted a fraction of the rows. On four case-sensitive engines that is a set
// of accounts that silently cannot sign in. Transaction enlistment is invisible from the other
// direction: the successful path's final row state is identical whether the writes were in one
// transaction or five, so only the connection they arrived on distinguishes them. And a
// concurrent write landing exactly between a read and the write that depends on it is not
// something a real engine can be timed into producing reliably.
//
// The driver stays deliberately ignorant of SQL. It answers any query with the rows it was
// given and any statement with the outcome it was given, and where a test needs to know WHICH
// row a statement addressed it reads the recorded ARGUMENTS rather than the query text, so
// nothing here breaks when a clause is rewritten.

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

// scriptedExec is one statement's answer: how many rows it changed, or the failure it met.
type scriptedExec struct {
	rowsAffected int64
	err          error
}

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
	if scripted.err != nil {
		return nil, scripted.err
	}
	return driver.RowsAffected(scripted.rowsAffected), nil
}

func (s *scriptedStmt) Query([]driver.Value) (driver.Rows, error) {
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
	if r.openErr != nil {
		return nil, r.openErr
	}
	return &r, nil
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
	openErr  error
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

// scanRow is one row of the opening scan, which selects id and email only.
func scanRow(id int64, email string) []driver.Value {
	return []driver.Value{id, email}
}

// scanResult is the opening scan's whole result set.
func scanResult(rows ...[]driver.Value) *scriptedRows {
	return &scriptedRows{cols: []string{"id", "email"}, values: rows}
}

// groupRow is one row of the re-read that decides a group, which also selects enabled.
func groupRow(id int64, email string, enabled bool) []driver.Value {
	return []driver.Value{id, email, enabled}
}

// groupResult is one whole answer to that re-read.
func groupResult(rows ...[]driver.Value) *scriptedRows {
	return &scriptedRows{values: rows}
}

// generationReadBack answers IncrementUserAuthStateGeneration's read of the value that landed,
// which is one column and would otherwise fail the Scan against this file's three-column
// default.
func generationReadBack(generation int64) *scriptedRows {
	return &scriptedRows{
		cols:   []string{"auth_state_generation"},
		values: [][]driver.Value{{generation}},
	}
}

// modelRow is one scripted result row for a sqlbuilder struct scan: one column per field the
// struct actually selects, carrying that field's value out of the model it was given. Built
// from the struct's own scan targets rather than from a hand-written column list, so a field
// added to either model changes this row with it instead of failing the Scan for a reason that
// has nothing to do with what the test asserts.
func modelRow(t *testing.T, model interface{}) *scriptedRows {
	t.Helper()

	addrs := sqlbuilder.NewStruct(model).For(sqlbuilder.SQLite).Addr(model)
	require.NotEmpty(t, addrs, "the model selects no columns at all, so nothing below would scan")

	cols := make([]string, len(addrs))
	vals := make([]driver.Value, len(addrs))
	for i, addr := range addrs {
		cols[i] = fmt.Sprintf("c%d", i)
		switch v := addr.(type) {
		case *int64:
			vals[i] = *v
		case *string:
			vals[i] = *v
		case *bool:
			vals[i] = *v
		case *time.Time:
			vals[i] = *v
		case *sql.NullInt64:
			if v.Valid {
				vals[i] = v.Int64
			}
		case *sql.NullTime:
			if v.Valid {
				vals[i] = v.Time
			}
		default:
			// Everything the switch does not name, by kind. A plain int, or a named integer
			// type like enums.PasswordPolicy, is NOT nullable, and scanning NULL into one
			// fails the Scan with "converting NULL to int is unsupported" for a reason that
			// has nothing to do with what the test asserts. models.Settings has nine such
			// fields, which is why this branch cannot simply leave the value nil.
			rv := reflect.ValueOf(addr).Elem()
			switch rv.Kind() {
			case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
				vals[i] = rv.Int()
			case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
				vals[i] = int64(rv.Uint())
			case reflect.Float32, reflect.Float64:
				vals[i] = rv.Float()
			case reflect.Slice:
				// []byte carries as itself; any other slice is not a driver.Value and stays
				// NULL, which is what a nullable column scans from.
				if rv.Type().Elem().Kind() == reflect.Uint8 {
					vals[i] = rv.Bytes()
				}
			}
		}
	}

	return &scriptedRows{cols: cols, values: [][]driver.Value{vals}}
}

// TestBackfillLowercaseEmails_FailsClosed walks every way storage can stop the pass and requires
// each one to come back as an error. A pass that swallows any of them reports success on a users
// table it only partly converted.
func TestBackfillLowercaseEmails_FailsClosed(t *testing.T) {
	boom := errors.New("connection reset by peer")

	tests := []struct {
		name    string
		driver  *scriptedDriver
		wantErr string
		why     string
	}{
		{
			name: "the scan dies part way through the users table",
			driver: &scriptedDriver{rows: []*scriptedRows{func() *scriptedRows {
				r := scanResult(scanRow(1, "Alice@x.com"), scanRow(2, "Bob@x.com"))
				r.failAt, r.err = 2, boom
				return r
			}()}},
			wantErr: "error iterating users for the lowercase email backfill",
			why: "sql.Rows reports a mid-iteration failure through Err() AFTER Next() returns false, " +
				"so without that check the pass sees a truncated table, converts what it read and calls it done",
		},
		{
			name: "the first row will not scan",
			driver: &scriptedDriver{rows: []*scriptedRows{{
				// An id no driver.Value conversion can put in an int64. A corrupt or
				// unexpected column type is the realistic cause.
				cols:   []string{"id", "email"},
				values: [][]driver.Value{{[]byte("not-a-number"), "Alice@x.com"}},
			}}},
			wantErr: "unable to scan user email",
			why:     "a row the pass cannot read is a row it cannot decide about, and skipping it silently leaves that address unconverted",
		},
		{
			name: "the re-read of the group is refused",
			driver: &scriptedDriver{rows: []*scriptedRows{
				scanResult(scanRow(1, "Alice@x.com")),
				{openErr: boom},
			}},
			wantErr: "unable to look up the users holding email",
			why: "that read is what decides the group, so a failure answered as \"no such group\" would " +
				"leave the address unconverted while reporting success",
		},
		{
			name: "the re-read's own result set dies part way through",
			driver: &scriptedDriver{rows: []*scriptedRows{
				scanResult(scanRow(1, "Alice@x.com")),
				func() *scriptedRows {
					r := groupResult(groupRow(1, "Alice@x.com", true))
					r.failAt, r.err = 1, boom
					return r
				}(),
			}},
			wantErr: "error iterating users holding email",
			why: "same hazard as the main scan, on the read that decides which row keeps the address: a " +
				"truncated group would hand it to a member the group does not contain",
		},
		{
			name: "a row of the re-read will not scan",
			driver: &scriptedDriver{rows: []*scriptedRows{
				scanResult(scanRow(1, "Alice@x.com")),
				{values: [][]driver.Value{{[]byte("not-a-number"), "Alice@x.com", true}}},
			}},
			wantErr: "unable to scan a user holding email",
			why:     "a member the pass cannot read is a member it cannot weigh, and the survivor rule is only total over the whole group",
		},
		{
			name: "the update that lowercases the survivor fails",
			driver: &scriptedDriver{
				rows: []*scriptedRows{
					scanResult(scanRow(1, "Alice@x.com")),
					groupResult(groupRow(1, "Alice@x.com", true)),
				},
				execs: []*scriptedExec{{err: boom}},
			},
			wantErr: "unable to lowercase the email of user id 1",
			why:     "the pass must not report a row as lowercased when the statement that would have done it failed",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			lowercased, disabled, err := scriptedDB(t, tc.driver).BackfillLowercaseEmails()

			require.Errorf(t, err, "the pass must fail closed here: %s", tc.why)
			assert.Containsf(t, err.Error(), tc.wantErr,
				"the error must name where it happened, because startup aborts on it and this string is all an operator gets: %v", err)
			assert.Zerof(t, lowercased, "a failed pass must not claim to have lowercased anything it did not finish")
			assert.Zerof(t, disabled, "and must not claim to have disabled anything either")
		})
	}
}

// TestBackfillLowercaseEmails_DisableFailureIsFatal is the collision half of the same property,
// separated because reaching it needs a group with two members and a survivor that is already
// lowercase, so the first statement the pass issues is the loser's disable.
//
// It is the one exit where swallowing the error would be actively dangerous rather than merely
// incomplete: the pass would report a loser as disabled while the row stayed enabled, holding an
// address that a credential path can now reach.
func TestBackfillLowercaseEmails_DisableFailureIsFatal(t *testing.T) {
	d := &scriptedDriver{
		rows: []*scriptedRows{
			// The scan returns the mixed-case loser only, because it keeps only rows that
			// differ from their own lowercase form.
			scanResult(scanRow(1, "Alice@x.com")),
			// The re-read then finds the lowercase survivor beside it, which takes the
			// address, so nothing needs lowercasing and the disable is the only write.
			groupResult(groupRow(1, "Alice@x.com", true), groupRow(2, "alice@x.com", true)),
		},
		execs: []*scriptedExec{{err: errors.New("deadlock found when trying to get lock")}},
	}

	lowercased, disabled, err := scriptedDB(t, d).BackfillLowercaseEmails()

	require.Error(t, err, "a disable that failed must stop startup, not be reported as done")
	assert.Contains(t, strings.ToLower(err.Error()), "unable to disable duplicate email user id 1",
		"the error must name the row, because that row is still enabled and still holds an address a credential path can now reach")
	assert.Zero(t, lowercased, "the survivor was already lowercase, so nothing was lowercased")
	assert.Zero(t, disabled, "and the disable failed, so nothing may be reported as disabled")
	assert.Equal(t, 1, d.rollbacks, "the transaction the disable opened must be rolled back")
	assert.Zero(t, d.commits, "and must not be committed")
}

// TestBackfillLowercaseEmails_ARevocationFailureRollsBackTheDisable is the atomicity of
// disableAndRevoke, asserted at every write AFTER the enabled-to-disabled transition rather
// than only at the transition itself.
//
// The transition is the cheap half to pin and the useless half to pin alone: a failure there
// leaves nothing behind whatever the code does. The expensive half is a failure at the
// generation advance, the refresh-token revocation or the session deletion, because the flag is
// already false by then. If any of those writes is not enlisted in the transaction the disable
// opened, the flag stays false while the credentials stay live at a generation that still
// matches the user's, which is the exact state disableAndRevoke exists to prevent, and it
// becomes reachable the moment an administrator re-enables the account.
//
// Rollback is asserted as the transaction being rolled back and never committed, plus the file's
// standing assertion that no statement reached the database outside it. Together those are the
// whole property: an engine that rolls a transaction back restores every row it touched, so
// pinning WHICH rows would be testing the engine. What is not the engine's, and what these cases
// hold, is that all five writes are inside one transaction. Each of the three tx arguments
// disableAndRevoke passes was mutated to nil and each mutation is caught here.
//
// The observable end state of the SUCCESSFUL path, on four real engines, is the data tier's:
// TestBackfillLowercaseEmails_DisablingALoserRevokesItsAuthState.
func TestBackfillLowercaseEmails_ARevocationFailureRollsBackTheDisable(t *testing.T) {
	boom := errors.New("connection reset by peer")

	// A group whose survivor is already lowercase, so the first statement is the loser's
	// guarded disable and everything after it is post-transition, holding one refresh token
	// and one session so both sweeps have something to write.
	script := func() *scriptedDriver {
		return &scriptedDriver{rows: []*scriptedRows{
			scanResult(scanRow(1, "Alice@x.com")),
			groupResult(groupRow(1, "Alice@x.com", true), groupRow(2, "alice@x.com", true)),
			generationReadBack(5),
			// Sessions before refresh tokens, which is the order disableAndRevoke issues
			// them in: the session rows are taken ahead of the grants that hang off them
			// (#139).
			modelRow(t, &models.UserSession{Id: 9}),
			modelRow(t, &models.RefreshToken{Id: 7}),
		}}
	}

	tests := []struct {
		name    string
		inject  func(*scriptedDriver)
		wantErr string
		why     string
	}{
		{
			name:    "the generation advance fails",
			inject:  func(d *scriptedDriver) { d.execs = []*scriptedExec{nil, {err: boom}} },
			wantErr: "unable to increment user auth state generation",
			why:     "the generation is what invalidates the authorization codes, which nothing deletes",
		},
		{
			name:    "the session sweep is refused",
			inject:  func(d *scriptedDriver) { d.rows[3] = &scriptedRows{openErr: boom} },
			wantErr: "unable to query database",
			why:     "no sessions read is not the same fact as no sessions held",
		},
		{
			name:    "deleting a session fails",
			inject:  func(d *scriptedDriver) { d.execs = []*scriptedExec{nil, nil, {err: boom}} },
			wantErr: "unable to delete userSession",
			why:     "a session that outlives the disable is usable again the moment the account is re-enabled",
		},
		{
			name:    "the refresh-token sweep is refused",
			inject:  func(d *scriptedDriver) { d.rows[4] = &scriptedRows{openErr: boom} },
			wantErr: "unable to query database",
			why:     "a sweep that cannot read the tokens must not be treated as a user with no tokens",
		},
		{
			name:    "revoking a refresh token fails",
			inject:  func(d *scriptedDriver) { d.execs = []*scriptedExec{nil, nil, nil, {err: boom}} },
			wantErr: "unable to update refreshToken",
			why:     "the disable is already written by now, so an unenlisted revocation would leave a live token on a disabled row",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			d := script()
			tc.inject(d)

			lowercased, disabled, err := scriptedDB(t, d).BackfillLowercaseEmails()

			require.Errorf(t, err, "the pass must fail closed here: %s", tc.why)
			assert.Containsf(t, err.Error(), tc.wantErr, "the error must name where it happened: %v", err)
			assert.Zero(t, lowercased, "nothing needed lowercasing in this group")
			assert.Zerof(t, disabled, "a disable whose revocation failed is not a disable: %s", tc.why)

			require.GreaterOrEqualf(t, d.execCount, 1,
				"the fixture is only meaningful if the transition write happened before the failure, and no statement reached the database at all")
			assert.Containsf(t, d.execArgs[0], "Alice@x.com",
				"the first statement must be the guarded disable, so this case is genuinely post-transition; its arguments were %v", d.execArgs[0])

			assert.Equal(t, 1, d.rollbacks, "the transaction the disable opened must be rolled back")
			assert.Zero(t, d.commits, "and must not be committed, whole or in part")
		})
	}
}

// TestBackfillLowercaseEmails_DecidesTheGroupAsItStandsNow is the concurrency property: the
// opening scan is a candidate list, not a decision, and every write is guarded on the address
// the re-read saw.
//
// It matters because the pass runs at startup while the OTHER replicas of the same deployment
// are serving, and both the account and the admin email endpoints write users.email. Acting on
// the scanned rows puts a collision's address back over an address a user has just changed to,
// and disables an account whose collision somebody has already resolved by hand, revoking every
// credential it holds (#283).
func TestBackfillLowercaseEmails_DecidesTheGroupAsItStandsNow(t *testing.T) {
	t.Run("a candidate whose address changed under the pass is left alone", func(t *testing.T) {
		d := &scriptedDriver{rows: []*scriptedRows{
			scanResult(scanRow(1, "Alice@x.com")),
			// Somebody committed an address change between the scan and here. It is no longer
			// a member of any group: every write path lowercases, so this is what the user
			// asked for.
			groupResult(groupRow(1, "alice-new@x.com", true)),
		}}

		lowercased, disabled, err := scriptedDB(t, d).BackfillLowercaseEmails()

		require.NoError(t, err, "a row that left the group is an ordinary outcome, not a failure")
		assert.Zero(t, lowercased)
		assert.Zero(t, disabled)
		assert.Zerof(t, d.execCount, "the pass must issue no statement at all here; it issued %d, so it wrote the scanned address back over the one the user changed to", d.execCount)
	})

	t.Run("a loser whose collision was resolved under the pass is left alone", func(t *testing.T) {
		d := &scriptedDriver{rows: []*scriptedRows{
			// Two mixed-case candidates.
			scanResult(scanRow(1, "Alice@x.com"), scanRow(2, "ALICE@x.com")),
			// By the time the group is decided, id 2 has been renamed out of the collision and
			// a lowercase row exists. So id 2 is not a member and must not be touched, and the
			// survivor is the row that now holds the address.
			groupResult(groupRow(1, "Alice@x.com", true), groupRow(3, "alice@x.com", true)),
			generationReadBack(5),
		}}

		lowercased, disabled, err := scriptedDB(t, d).BackfillLowercaseEmails()

		require.NoError(t, err)
		assert.Zero(t, lowercased, "the survivor already holds the lowercase address")
		assert.Equal(t, 1, disabled, "exactly the one remaining mixed-case member must be disabled")

		require.NotEmpty(t, d.execArgs, "no statement was issued, so nothing was disabled")
		assert.Containsf(t, d.execArgs[0], int64(1), "the disable must address id 1: %v", d.execArgs[0])
		assert.Containsf(t, d.execArgs[0], "Alice@x.com",
			"and must carry the address the re-read saw, or it is not guarded at all: %v", d.execArgs[0])
		for i, args := range d.execArgs {
			assert.NotContainsf(t, args, int64(2),
				"statement %d addresses id 2, which left the collision before the pass reached it: %v", i, args)
		}
	})

	t.Run("the survivor's write carries the address the re-read saw", func(t *testing.T) {
		d := &scriptedDriver{rows: []*scriptedRows{
			scanResult(scanRow(1, "Alice@x.com")),
			groupResult(groupRow(1, "Alice@x.com", true)),
		}}

		lowercased, disabled, err := scriptedDB(t, d).BackfillLowercaseEmails()

		require.NoError(t, err)
		assert.Equal(t, 1, lowercased)
		assert.Zero(t, disabled)

		require.Len(t, d.execArgs, 1, "one row, one statement")
		assert.Contains(t, d.execArgs[0], "alice@x.com", "the address being written")
		assert.Contains(t, d.execArgs[0], int64(1), "the row it is written to")
		assert.Containsf(t, d.execArgs[0], "Alice@x.com",
			"and the address the row must still hold for the write to land; without it this statement overwrites whatever is there now: %v", d.execArgs[0])
	})

	t.Run("a guard that reports no row makes the group be decided again", func(t *testing.T) {
		d := &scriptedDriver{
			rows: []*scriptedRows{
				scanResult(scanRow(1, "Alice@x.com")),
				groupResult(groupRow(1, "Alice@x.com", true)),
				// Second attempt: the row is gone from the group entirely.
				groupResult(),
			},
			execs: []*scriptedExec{{rowsAffected: 0}},
		}

		lowercased, disabled, err := scriptedDB(t, d).BackfillLowercaseEmails()

		require.NoError(t, err, "losing a race is not a storage failure")
		assert.Zerof(t, lowercased, "the guard reported no row, so nothing was lowercased")
		assert.Zero(t, disabled)
		assert.Equalf(t, 3, d.queryCount,
			"the group must be read again after a guard reports no row: the scan plus two re-reads is 3, and %d means the pass either gave up or never recomputed", d.queryCount)
		assert.Equal(t, 1, d.execCount, "and must not reissue a write against a decision it has already been told is stale")
	})

	t.Run("a disable that reports no row makes the group be decided again", func(t *testing.T) {
		d := &scriptedDriver{
			rows: []*scriptedRows{
				scanResult(scanRow(1, "Alice@x.com")),
				groupResult(groupRow(1, "Alice@x.com", true), groupRow(2, "alice@x.com", true)),
				// Second attempt: somebody disabled id 1 first, so there is nothing left to do.
				groupResult(groupRow(1, "Alice@x.com", false), groupRow(2, "alice@x.com", true)),
				generationReadBack(5),
			},
			execs: []*scriptedExec{{rowsAffected: 0}},
		}

		lowercased, disabled, err := scriptedDB(t, d).BackfillLowercaseEmails()

		require.NoError(t, err)
		assert.Zero(t, lowercased)
		assert.Zerof(t, disabled, "a compare-and-set that changed no row disabled nobody, and counting it would report a revocation that never happened")
		assert.Equal(t, 3, d.queryCount, "the scan plus two re-reads")
		assert.Equal(t, 1, d.execCount, "the second attempt sees the row already disabled and writes nothing")
		assert.Equalf(t, 1, d.commits,
			"a lost race must COMMIT the empty transaction rather than roll it back: rolling back would make an ordinary outcome indistinguishable from a storage fault")
		assert.Zero(t, d.rollbacks)
	})
}

// TestBackfillLowercaseEmails_GivesUpRatherThanSpinning bounds the recompute. A group whose rows
// keep moving is logged and skipped, not retried forever and not returned as an error.
//
// Not an error, deliberately. Returning one aborts startup, and what is left behind is not a
// regression: a row still spelled in mixed case is a row no credential path could reach before
// this change either, because every path lowercases the address it looks up. Failing closed here
// would hand a user who changes their own address twice during a rolling deployment the ability
// to stop a replica from starting.
func TestBackfillLowercaseEmails_GivesUpRatherThanSpinning(t *testing.T) {
	group := groupResult(groupRow(1, "Alice@x.com", true))

	d := &scriptedDriver{
		rows: []*scriptedRows{
			scanResult(scanRow(1, "Alice@x.com")),
			group, group, group,
		},
		// Every attempt's guard reports no row, which is a writer changing the address again
		// between each read and each write.
		execs: []*scriptedExec{{rowsAffected: 0}, {rowsAffected: 0}, {rowsAffected: 0}},
	}

	lowercased, disabled, err := scriptedDB(t, d).BackfillLowercaseEmails()

	require.NoError(t, err, "giving up on a group must not abort startup")
	assert.Zero(t, lowercased)
	assert.Zero(t, disabled)
	assert.Equalf(t, emailGroupAttempts, d.execCount,
		"the pass must try exactly emailGroupAttempts times and stop; %d means it is unbounded or gave up early", d.execCount)
	assert.Equal(t, emailGroupAttempts+1, d.queryCount, "the scan plus one re-read per attempt")
}

// The console half of the audit emission has no other observable: the target is a slog.Info call
// and nothing else, which is why forcing that branch to false once left the whole four-engine data
// tier green. testutil.CaptureSlog is what reads it.
// messagesAt returns the messages logged at one level, in order.
func messagesAt(logs *testutil.SlogCapture, level slog.Level) []string {
	out := []string{}
	for _, record := range logs.Records() {
		if record.Level == level {
			out = append(out, record.Message)
		}
	}
	return out
}

// auditedGroup is the script for one collision the pass resolves in full: a survivor already
// spelled in lowercase, one enabled loser holding a refresh token and a session, and the
// settings row auditRevokedUserAuthState reads after the commit to decide where the event goes.
func auditedGroup(t *testing.T, console bool, database bool) *scriptedDriver {
	t.Helper()

	return &scriptedDriver{rows: []*scriptedRows{
		scanResult(scanRow(1, "Alice@x.com")),
		groupResult(groupRow(1, "Alice@x.com", true), groupRow(2, "alice@x.com", true)),
		generationReadBack(5),
		// Sessions before refresh tokens, which is the order disableAndRevoke issues them
		// in: the session rows are taken ahead of the grants that hang off them (#139).
		modelRow(t, &models.UserSession{Id: 9}),
		modelRow(t, &models.RefreshToken{Id: 7}),
		modelRow(t, &models.Settings{
			Id:                         1,
			AuditLogsInConsoleEnabled:  console,
			AuditLogsInDatabaseEnabled: database,
		}),
	}}
}

// auditRowsWritten counts the statements whose arguments carry the audit event name, which is
// the INSERT into audit_logs and nothing else in this sequence. Read off the recorded arguments
// rather than the query text, like everything else in this file, so a rewritten clause does not
// break it.
func auditRowsWritten(d *scriptedDriver) int {
	d.mu.Lock()
	defer d.mu.Unlock()

	written := 0
	for _, args := range d.execArgs {
		for _, arg := range args {
			if s, ok := arg.(string); ok && s == constants.AuditRevokedUserAuthState {
				written++
			}
		}
	}
	return written
}

// TestBackfillLowercaseEmails_TheAuditSettingsDecideBothTargets pins where the revocation's
// audit event goes, in both polarities of both targets.
//
// The rule is a hand-copy and that is why it needs pinning. auditRevokedUserAuthState writes the
// event out itself, because handlers.LogRevokedUserAuthState and AuditLogger both live in the
// authserver module and core cannot import them, so nothing but a test holds the copy to the
// original. The database target was pinned in both polarities by the data tier from the start;
// the console target was pinned in neither, and forcing its branch to false left every engine
// green (#283, final review round 4).
//
// The console half is not the lesser one. The audit-log documentation recommends console output
// precisely where the database is the resource being audited, and this event is the server
// disabling an account and destroying every credential it held with nobody having asked.
func TestBackfillLowercaseEmails_TheAuditSettingsDecideBothTargets(t *testing.T) {
	tests := []struct {
		name     string
		console  bool
		database bool
	}{
		{name: "both targets on", console: true, database: true},
		{name: "console only", console: true, database: false},
		{name: "database only", console: false, database: true},
		{name: "both targets off", console: false, database: false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			logs := testutil.CaptureSlog(t)
			d := auditedGroup(t, tc.console, tc.database)

			_, disabled, err := scriptedDB(t, d).BackfillLowercaseEmails()

			require.NoError(t, err, "the audit emission is non-fatal and must never fail the pass")
			require.Equal(t, 1, disabled,
				"the fixture only says anything about auditing if the loser was actually disabled")

			// Read off the `event` attribute rather than the message. The console record is
			// auditlog.LogToConsole's now, shared with the authserver's AuditLogger, and its
			// message is the same "audit event" for every event: the name a consumer filters
			// on is an attribute (#320 decision 7).
			console := 0
			for _, record := range logs.Records() {
				if record.Level == slog.LevelInfo && record.Attrs["event"] == constants.AuditRevokedUserAuthState {
					console++
				}
			}
			if tc.console {
				assert.Equal(t, 1, console,
					"audit_logs_in_console_enabled is on, so the event must reach the console exactly once")
				// And carrying its payload rather than only its name. `reason` is how the
				// event's contract says a consumer tells this site apart from the four
				// credential sites that raise the same event.
				for _, record := range logs.Records() {
					if record.Attrs["event"] != constants.AuditRevokedUserAuthState {
						continue
					}
					details, ok := record.Attrs["details"].(map[string]interface{})
					require.True(t, ok, "the console record must carry the details as a map")
					assert.Equal(t, constants.RevocationReasonEmailCollisionBackfill, details["reason"])
					assert.Equal(t, int64(1), details["userId"])
				}
			} else {
				assert.Zero(t, console,
					"audit_logs_in_console_enabled is off, so the operator has turned this event's console copy off and it must not appear")
			}

			if tc.database {
				assert.Equal(t, 1, auditRowsWritten(d),
					"audit_logs_in_database_enabled is on, so exactly one audit_logs row must be written")
			} else {
				assert.Zero(t, auditRowsWritten(d),
					"audit_logs_in_database_enabled is off, so no audit_logs row may be written")
			}

			// The emission must not report a failure it did not have. This driver answers every
			// statement with driver.RowsAffected, whose LastInsertId refuses exactly as pgx's
			// stdlib wrapper does, so a call that reads the id back logs a persistence failure
			// over a row that landed. That is what jammed the operator's only alarm for the
			// audit trail on PostgreSQL and SQL Server (#283).
			assert.Emptyf(t, messagesAt(logs, slog.LevelError),
				"nothing here failed, so nothing may be logged at ERROR; got %v",
				messagesAt(logs, slog.LevelError))
		})
	}
}

// TestInsertAuditLogWithoutId_SurvivesADriverThatRefusesLastInsertId pins the helper itself
// against the driver behaviour it exists for.
//
// database/sql's own driver.RowsAffected is the faithful stand-in: it is literally what pgx's
// stdlib wrapper returns from an Exec, and its LastInsertId reports "not supported by this
// driver". go-mssqldb refuses the same call with its own wording.
func TestInsertAuditLogWithoutId_SurvivesADriverThatRefusesLastInsertId(t *testing.T) {
	db := scriptedDB(t, &scriptedDriver{})

	err := db.insertAuditLogWithoutId(nil, &models.AuditLog{
		AuditEvent: constants.AuditRevokedUserAuthState,
		Details:    "{}",
	})
	require.NoError(t, err,
		"the row landed, so the helper must report success on a driver that cannot hand back an id")

	// What keeps the case from being vacuous: the same insert through CreateAuditLog, on the
	// same driver, is the failure the helper exists to avoid. If this half ever stops failing,
	// CreateAuditLog has stopped reading the id back, the helper has no further reason to exist,
	// and this line is where that gets noticed.
	err = db.CreateAuditLog(nil, &models.AuditLog{
		AuditEvent: constants.AuditRevokedUserAuthState,
		Details:    "{}",
	})
	require.Error(t, err,
		"CreateAuditLog reads the id back, which is why a caller inside commondb cannot use it")
	assert.Contains(t, err.Error(), "unable to get last insert id",
		"and the failure is the id read rather than the insert")
}

// TestBackfillLowercaseEmails_TheUsersRowIsTakenFirst pins that the guarded disable is the first
// statement disableAndRevoke writes.
//
// The reason is local to that transaction. The guarded disable is its classification: the row
// it affects is the transition, and affecting none means somebody else already disabled this
// loser, so the function returns having touched no session and no grant. A statement hoisted
// above it, a generation read or the session read moved up for tidiness, would run on the
// branch that is supposed to touch nothing, and would take rows that a termination or a
// ceremony for the same account is about to want, for no outcome at all. Nothing about the
// function's shape enforces the order, so a test is what holds it.
//
// The statement is identified by its arguments rather than by its query text, which is this
// file's convention: the guarded disable is the only statement in the sequence that carries the
// loser's expected address, because that address is the compare half of its compare-and-set.
func TestBackfillLowercaseEmails_TheUsersRowIsTakenFirst(t *testing.T) {
	const loserId, loserEmail = int64(1), "Alice@x.com"

	d := auditedGroup(t, false, false)
	_, disabled, err := scriptedDB(t, d).BackfillLowercaseEmails()

	require.NoError(t, err)
	require.Equal(t, 1, disabled, "the fixture only says anything about ordering if a loser was disabled")

	d.mu.Lock()
	defer d.mu.Unlock()
	require.NotEmpty(t, d.execArgs, "the pass must have written something")

	carriesTheGuard := func(args []driver.Value) bool {
		sawId, sawEmail := false, false
		for _, arg := range args {
			if id, ok := arg.(int64); ok && id == loserId {
				sawId = true
			}
			if email, ok := arg.(string); ok && email == loserEmail {
				sawEmail = true
			}
		}
		return sawId && sawEmail
	}

	assert.True(t, carriesTheGuard(d.execArgs[0]),
		"the guarded disable of the users row must be the FIRST statement the transaction writes, "+
			"because it is what decides whether anything below it runs at all; found %v",
		d.execArgs[0])
}

// auditDetails returns the decoded details of the one AuditRevokedUserAuthState row the pass
// wrote, read off the recorded INSERT arguments like everything else in this file.
func auditDetails(t *testing.T, d *scriptedDriver) map[string]interface{} {
	t.Helper()
	d.mu.Lock()
	defer d.mu.Unlock()

	for _, args := range d.execArgs {
		isAudit := false
		for _, arg := range args {
			if s, ok := arg.(string); ok && s == constants.AuditRevokedUserAuthState {
				isAudit = true
			}
		}
		if !isAudit {
			continue
		}
		for _, arg := range args {
			s, ok := arg.(string)
			if !ok || !strings.Contains(s, "terminatedSessionIdentifiers") {
				continue
			}
			var details map[string]interface{}
			require.NoError(t, json.Unmarshal([]byte(s), &details), "the audit details must be JSON")
			return details
		}
	}
	require.Fail(t, "no AuditRevokedUserAuthState row was written")
	return nil
}

// TestBackfillLowercaseEmails_ARetriedRevocationAuditsOnlyTheAttemptThatCommitted pins
// disableAndRevoke's sweep as attempt-local.
//
// inTransaction reruns the body when the engine aborts it as a deadlock victim (#301), and the
// body used to append every session it deleted and every token it revoked to a sweep declared
// OUTSIDE it. A rerun then audited the rolled-back attempt's rows on top of its own, and
// AuditRevokedUserAuthState is a durable security record: it would name sessions this call did
// not terminate and tokens it did not revoke. The engine's rollback undoes the rows; nothing
// undoes what Go remembered about them.
//
// The "different rows" shapes are what separate a sweep rebuilt at attempt entry from an
// accumulator that is merely reset before being appended to: a hoisted accumulator fails both
// on LENGTH, an accumulator reset at entry passes both, and only the content of the audit tells
// them apart when the two attempts saw different rows, which they do whenever a concurrent
// termination or rotation is what caused the deadlock in the first place.
func TestBackfillLowercaseEmails_ARetriedRevocationAuditsOnlyTheAttemptThatCommitted(t *testing.T) {
	// The group, then attempt one of the loser's disable up to the statement the engine
	// aborts, then attempt two in full, then the settings row the audit reads after the commit.
	// Two sessions rows and two token rows are scripted so each attempt reads its own.
	// A nil result set means that read is never reached on that attempt, which is the token read
	// on a first attempt aborted while deleting sessions.
	script := func(deadlockAt int, firstSessions, secondSessions, firstTokens, secondTokens *scriptedRows) *scriptedDriver {
		rows := []*scriptedRows{
			scanResult(scanRow(1, "Alice@x.com")),
			groupResult(groupRow(1, "Alice@x.com", true), groupRow(2, "alice@x.com", true)),
			generationReadBack(5),
		}
		for _, r := range []*scriptedRows{firstSessions, firstTokens, generationReadBack(6), secondSessions, secondTokens} {
			if r != nil {
				rows = append(rows, r)
			}
		}
		rows = append(rows, modelRow(t, &models.Settings{Id: 1, AuditLogsInDatabaseEnabled: true}))

		execs := make([]*scriptedExec, deadlockAt+1)
		execs[deadlockAt] = &scriptedExec{err: errDeadlock}
		return &scriptedDriver{rows: rows, execs: execs}
	}
	// sessions and tokens are ONE result set each, with one row per identifier, because each is
	// answered by one query.
	sessions := func(ids ...string) *scriptedRows {
		var out *scriptedRows
		for i, id := range ids {
			row := modelRow(t, &models.UserSession{Id: int64(9 + i), SessionIdentifier: id})
			if out == nil {
				out = row
			} else {
				out.values = append(out.values, row.values...)
			}
		}
		return out
	}
	tokens := func(jtis ...string) *scriptedRows {
		var out *scriptedRows
		for i, jti := range jtis {
			row := modelRow(t, &models.RefreshToken{Id: int64(7 + i), RefreshTokenJti: jti})
			if out == nil {
				out = row
			} else {
				out.values = append(out.values, row.values...)
			}
		}
		return out
	}
	// Statement indexes within one attempt: 0 the guarded disable, 1 the generation advance,
	// then one delete per session, then one update per token. The deadlock has to land AFTER
	// the first attempt recorded something, or a hoisted accumulator has nothing to carry over
	// and the case proves nothing: the session cases therefore give the first attempt two
	// sessions and abort the second delete, and the token cases one session and abort the one
	// token revocation.
	const atSecondSessionDelete, atTokenRevocationAfterOneSession = 3, 3

	tests := []struct {
		name         string
		d            *scriptedDriver
		wantSessions []interface{}
		wantJtis     []interface{}
	}{
		{
			name: "the same sessions, deleted by both attempts, are named once each",
			d: script(atSecondSessionDelete,
				sessions("sess-9", "sess-10"), sessions("sess-9", "sess-10"),
				nil, tokens("jti-7")),
			wantSessions: []interface{}{"sess-9", "sess-10"},
			wantJtis:     []interface{}{"jti-7"},
		},
		{
			name: "a session the rolled-back attempt deleted and the committed one did not see is absent",
			d: script(atSecondSessionDelete,
				sessions("sess-rolled-back", "sess-rolled-back-too"), sessions("sess-committed"),
				nil, tokens("jti-7")),
			wantSessions: []interface{}{"sess-committed"},
			wantJtis:     []interface{}{"jti-7"},
		},
		{
			name: "the same token, revoked by both attempts, is named once",
			d: script(atTokenRevocationAfterOneSession,
				sessions("sess-9"), sessions("sess-9"),
				tokens("jti-7"), tokens("jti-7")),
			wantSessions: []interface{}{"sess-9"},
			wantJtis:     []interface{}{"jti-7"},
		},
		{
			name: "a token the rolled-back attempt revoked and the committed one did not see is absent",
			d: script(atTokenRevocationAfterOneSession,
				sessions("sess-9"), sessions("sess-9"),
				tokens("jti-rolled-back"), tokens("jti-committed")),
			wantSessions: []interface{}{"sess-9"},
			wantJtis:     []interface{}{"jti-committed"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			recordBackoff(t)
			db := retryingDB(t, tc.d)

			_, disabled, err := db.BackfillLowercaseEmails()

			require.NoError(t, err, "the rerun succeeded, so the pass does")
			require.Equal(t, 1, disabled, "the loser was disabled exactly once, by the attempt that committed")
			require.Equal(t, 1, tc.d.rollbacks, "the fixture only says anything if the first attempt was really rolled back")
			require.Equal(t, 1, tc.d.commits)

			details := auditDetails(t, tc.d)
			assert.Equal(t, tc.wantSessions, details["terminatedSessionIdentifiers"],
				"the audit names the sessions the COMMITTED attempt terminated, each once, and nothing the rolled-back attempt touched")
			assert.Equal(t, tc.wantJtis, details["revokedRefreshTokenJtis"],
				"and the tokens the committed attempt revoked, each once, and nothing the rolled-back attempt touched")
			assert.EqualValues(t, 6, details["newGeneration"], "the generation is the one the committed attempt landed")
			assert.EqualValues(t, 5, details["oldGeneration"])
		})
	}
}

// TestBackfillLowercaseEmails_ARetryThatRevokesNothingAuditsNothing holds today's two silent
// exits across a rerun: a rerun whose guarded disable matches nothing is not a transition, and
// a body that exhausts its attempts committed nothing. Neither may emit the event, because the
// event attests to a revocation that happened.
func TestBackfillLowercaseEmails_ARetryThatRevokesNothingAuditsNothing(t *testing.T) {
	t.Run("the rerun finds the row already disabled", func(t *testing.T) {
		recordBackoff(t)
		d := &scriptedDriver{
			rows: []*scriptedRows{
				scanResult(scanRow(1, "Alice@x.com")),
				groupResult(groupRow(1, "Alice@x.com", true), groupRow(2, "alice@x.com", true)),
				generationReadBack(5),
				modelRow(t, &models.UserSession{Id: 9, SessionIdentifier: "sess-9"}),
				// Attempt two: the guarded disable matches nothing, so the body returns before
				// reading anything else; the group is then re-read and found empty.
			},
			// Attempt one deadlocks deleting the session; attempt two's disable affects no row.
			execs: []*scriptedExec{nil, nil, {err: errDeadlock}, {rowsAffected: 0}},
		}
		db := retryingDB(t, d)

		_, disabled, err := db.BackfillLowercaseEmails()

		require.NoError(t, err)
		assert.Zero(t, disabled, "a rerun that transitioned nothing disabled nothing")
		assert.Equal(t, 1, d.rollbacks)
		assert.Equal(t, 1, d.commits, "the empty second attempt still commits, as a no-op transaction")
		assert.Zero(t, auditRowsWritten(d), "and nothing is audited, because nothing was taken away")
	})

	t.Run("the attempts are exhausted", func(t *testing.T) {
		recordBackoff(t)
		d := &scriptedDriver{
			rows: []*scriptedRows{
				scanResult(scanRow(1, "Alice@x.com")),
				groupResult(groupRow(1, "Alice@x.com", true), groupRow(2, "alice@x.com", true)),
				generationReadBack(5), modelRow(t, &models.UserSession{Id: 9, SessionIdentifier: "sess-9"}),
				generationReadBack(5), modelRow(t, &models.UserSession{Id: 9, SessionIdentifier: "sess-9"}),
				generationReadBack(5), modelRow(t, &models.UserSession{Id: 9, SessionIdentifier: "sess-9"}),
			},
			execs: []*scriptedExec{
				nil, nil, {err: errDeadlock},
				nil, nil, {err: errDeadlock},
				nil, nil, {err: errDeadlock},
			},
		}
		db := retryingDB(t, d)

		_, disabled, err := db.BackfillLowercaseEmails()

		require.Error(t, err, "three deadlocks are the pass's failure, not something it hides")
		assert.ErrorIs(t, err, errDeadlock)
		assert.Zero(t, disabled)
		assert.Equal(t, 3, d.rollbacks)
		assert.Zero(t, d.commits)
		assert.Zero(t, auditRowsWritten(d), "nothing committed, so nothing is attested to")
	})
}
