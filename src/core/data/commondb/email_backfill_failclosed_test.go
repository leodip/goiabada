package commondb

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/huandu/go-sqlbuilder"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// This file pins ONE property of BackfillLowercaseEmails: every way storage can fail it comes
// back to the caller as an error. Nothing else about the pass is tested here; the rule itself is
// TestPickEmailSurvivor's, and the four-engine behaviour is the data tier's.
//
// It needs a driver rather than a real engine because the failures worth pinning are the ones no
// engine can be asked for on demand. A result set that yields two rows and then dies is what a
// dropped connection or a server-side timeout looks like part way through a scan, and it is the
// exit whose absence is invisible: sql.Rows reports it through Err() after Next() returns false,
// so a pass that forgets to check reads a TRUNCATED users table, decides it has seen every group,
// and reports success having converted a fraction of the rows. On four case-sensitive engines
// that is a set of accounts that silently cannot sign in.
//
// The driver is deliberately the smallest thing that can express a script. It answers any query
// with the rows it was given and any statement with the result it was given, so it says nothing
// about SQL and cannot drift as the queries change.

// scriptedDriver answers every query with rows and every exec with an outcome, in the order the
// pass makes them. A nil entry means "succeed with nothing", which is what a lookup that finds no
// row and an update that changes one row both look like from here.
type scriptedDriver struct {
	// rows is consumed one entry per query, in order. Running past the end answers with an
	// empty result set rather than failing, so a test only has to script the calls it cares
	// about.
	rows []*scriptedRows
	// execErr, when non-nil, is returned by every exec. The pass issues at most one exec per
	// group, so failing all of them and scripting one group is enough to reach any of them.
	execErr error

	queryCount int
}

func (d *scriptedDriver) Connect(context.Context) (driver.Conn, error) {
	return &scriptedConn{d: d}, nil
}
func (d *scriptedDriver) Driver() driver.Driver            { return d }
func (d *scriptedDriver) Open(string) (driver.Conn, error) { return &scriptedConn{d: d}, nil }

type scriptedConn struct{ d *scriptedDriver }

func (c *scriptedConn) Prepare(query string) (driver.Stmt, error) {
	return &scriptedStmt{d: c.d, query: query}, nil
}
func (c *scriptedConn) Close() error              { return nil }
func (c *scriptedConn) Begin() (driver.Tx, error) { return scriptedTx{}, nil }

type scriptedTx struct{}

func (scriptedTx) Commit() error   { return nil }
func (scriptedTx) Rollback() error { return nil }

type scriptedStmt struct {
	d     *scriptedDriver
	query string
}

func (s *scriptedStmt) Close() error  { return nil }
func (s *scriptedStmt) NumInput() int { return -1 }

func (s *scriptedStmt) Exec([]driver.Value) (driver.Result, error) {
	if s.d.execErr != nil {
		return nil, s.d.execErr
	}
	return driver.RowsAffected(1), nil
}

func (s *scriptedStmt) Query([]driver.Value) (driver.Rows, error) {
	i := s.d.queryCount
	s.d.queryCount++
	if i < len(s.d.rows) && s.d.rows[i] != nil {
		r := *s.d.rows[i]
		if r.openErr != nil {
			return nil, r.openErr
		}
		return &r, nil
	}
	return &scriptedRows{}, nil
}

// scriptedRows yields values and then either ends or fails. failAfter counts rows emitted
// before the failure, so 0 fails immediately and 2 fails after two good rows, which is the
// shape that separates "the query failed" from "the scan stopped half way".
type scriptedRows struct {
	values [][]driver.Value
	failAt int
	err    error
	// openErr fails the query itself rather than its iteration, which is the difference
	// between a statement the engine refused and a result set that died being read.
	openErr  error
	returned int
}

func (r *scriptedRows) Columns() []string { return []string{"id", "email", "enabled"} }
func (r *scriptedRows) Close() error      { return nil }

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
	return NewCommonDatabase(db, sqlbuilder.SQLite, false)
}

func userRow(id int64, email string, enabled bool) []driver.Value {
	return []driver.Value{id, email, enabled}
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
			driver: &scriptedDriver{rows: []*scriptedRows{{
				values: [][]driver.Value{
					userRow(1, "Alice@x.com", true),
					userRow(2, "Bob@x.com", true),
				},
				failAt: 2,
				err:    boom,
			}}},
			wantErr: "error iterating users for the lowercase email backfill",
			why: "sql.Rows reports a mid-iteration failure through Err() AFTER Next() returns false, " +
				"so without that check the pass sees a truncated table, converts what it read and calls it done",
		},
		{
			name: "the first row will not scan",
			driver: &scriptedDriver{rows: []*scriptedRows{{
				// An id no driver.Value conversion can put in an int64. A corrupt or
				// unexpected column type is the realistic cause.
				values: [][]driver.Value{{[]byte("not-a-number"), "Alice@x.com", true}},
			}}},
			wantErr: "unable to scan user email",
			why:     "a row the pass cannot read is a row it cannot decide about, and skipping it silently leaves that address unconverted",
		},
		{
			name: "the lookup of the row already spelled in lowercase fails",
			driver: &scriptedDriver{rows: []*scriptedRows{
				{values: [][]driver.Value{userRow(1, "Alice@x.com", true)}},
				{openErr: boom},
			}},
			wantErr: "unable to look up the user holding email",
			why: "that lookup is what finds the survivor of a group, so a failure answered as " +
				"\"no such row\" would hand the address to a member the group does not contain",
		},
		{
			name: "the lookup's own result set dies part way through",
			driver: &scriptedDriver{rows: []*scriptedRows{
				{values: [][]driver.Value{userRow(1, "Alice@x.com", true)}},
				{values: [][]driver.Value{userRow(2, "alice@x.com", true)}, failAt: 1, err: boom},
			}},
			wantErr: "error iterating users holding email",
			why:     "same hazard as the main scan, on the query that decides which row keeps the address",
		},
		{
			name: "the update that lowercases the survivor fails",
			driver: &scriptedDriver{
				rows:    []*scriptedRows{{values: [][]driver.Value{userRow(1, "Alice@x.com", true)}}},
				execErr: boom,
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
// lowercase, so the only statement the pass issues is the loser's disable.
//
// It is the one exit where swallowing the error would be actively dangerous rather than merely
// incomplete: the pass would report a loser as disabled while the row stayed enabled, holding an
// address that a credential path can now reach.
func TestBackfillLowercaseEmails_DisableFailureIsFatal(t *testing.T) {
	d := &scriptedDriver{
		// The scan returns the mixed-case loser only, because the pass keeps only rows that
		// differ from their own lowercase form.
		rows: []*scriptedRows{
			{values: [][]driver.Value{userRow(1, "Alice@x.com", true)}},
			// The lookup then finds the lowercase survivor, which becomes the group's second
			// member and takes the address, so nothing needs lowercasing.
			{values: [][]driver.Value{userRow(2, "alice@x.com", true)}},
		},
		execErr: errors.New("deadlock found when trying to get lock"),
	}

	lowercased, disabled, err := scriptedDB(t, d).BackfillLowercaseEmails()

	require.Error(t, err, "a disable that failed must stop startup, not be reported as done")
	assert.Contains(t, strings.ToLower(err.Error()), "unable to disable duplicate email user id 1",
		"the error must name the row, because that row is still enabled and still holds an address a credential path can now reach")
	assert.Zero(t, lowercased, "the survivor was already lowercase, so nothing was lowercased")
	assert.Zero(t, disabled, "and the disable failed, so nothing may be reported as disabled")
}
