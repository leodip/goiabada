package commondb

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/huandu/go-sqlbuilder"
	"github.com/leodip/goiabada/core/models"
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

	openTx    int
	commits   int
	rollbacks int
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
	return nil
}

func (t *scriptedTx) Rollback() error {
	t.c.d.mu.Lock()
	defer t.c.d.mu.Unlock()
	t.c.inTx = false
	t.c.d.openTx--
	t.c.d.rollbacks++
	return nil
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
			// Anything else is a nullable the pass does not read, and NULL is what a
			// nullable scans from.
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
			modelRow(t, &models.RefreshToken{Id: 7}),
			modelRow(t, &models.UserSession{Id: 9}),
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
			name:    "the refresh-token sweep is refused",
			inject:  func(d *scriptedDriver) { d.rows[3] = &scriptedRows{openErr: boom} },
			wantErr: "unable to query database",
			why:     "a sweep that cannot read the tokens must not be treated as a user with no tokens",
		},
		{
			name:    "revoking a refresh token fails",
			inject:  func(d *scriptedDriver) { d.execs = []*scriptedExec{nil, nil, {err: boom}} },
			wantErr: "unable to update refreshToken",
			why:     "the disable is already written by now, so an unenlisted revocation would leave a live token on a disabled row",
		},
		{
			name:    "the session sweep is refused",
			inject:  func(d *scriptedDriver) { d.rows[4] = &scriptedRows{openErr: boom} },
			wantErr: "unable to query database",
			why:     "same as the token sweep: no sessions read is not the same fact as no sessions held",
		},
		{
			name:    "deleting a session fails",
			inject:  func(d *scriptedDriver) { d.execs = []*scriptedExec{nil, nil, nil, {err: boom}} },
			wantErr: "unable to delete userSession",
			why:     "a session that outlives the disable is usable again the moment the account is re-enabled",
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
