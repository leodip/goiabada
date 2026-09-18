package commondb

import (
	"database/sql/driver"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ScanEmailCase against the scripted driver, which is the only place its three storage exits can
// be asked for: no real engine can be told to refuse this query, to hand back a row whose id does
// not scan, or to die after a good row.
//
// Every case here holds one property, and it is fail-closed rather than complete-looking. The
// caller above this method, datafactory.CheckEmailCaseBeforeMigrating, reads the rows it is given
// and nothing else, so an empty or short result reads as "no address collides" and the upgrade
// crosses migration 000047 having looked at a fraction of the table. A storage failure turned
// into a clean result is therefore not a lost error message: it is the pre-flight passing on rows
// it never saw, which is the outcome the pre-flight exists to prevent (#351).
//
// The backfill this replaced had scan and iteration failure cases of its own. The replacement
// method arrived without them, and all three of its error exits could be neutralized with the
// whole core tier staying green, which is what these cases close.

// emailCaseColumns is what the query selects, in order. database/sql refuses a Scan whose
// destination count differs from the result set's, so the fixtures state it rather than leaning
// on the scripted driver's default.
var emailCaseColumns = []string{"id", "email", "LOWER(email)"}

func TestScanEmailCase_ReadsEveryRowAsStoredAndAsTheEngineLoweredIt(t *testing.T) {
	d := &scriptedDriver{rows: []*scriptedRows{{
		cols: emailCaseColumns,
		values: [][]driver.Value{
			{int64(1), "Alice@x.com", "alice@x.com"},
			{int64(2), "bob@x.com", "bob@x.com"},
		},
	}}}
	db := scriptedDB(t, d)

	rows, err := db.ScanEmailCase()

	require.NoError(t, err)
	require.Len(t, rows, 2)
	assert.Equal(t, int64(1), rows[0].Id)
	assert.Equal(t, "Alice@x.com", rows[0].Email)
	assert.Equal(t, "alice@x.com", rows[0].EngineLowered)
	assert.Equal(t, int64(2), rows[1].Id)
	assert.Equal(t, "bob@x.com", rows[1].Email)
	assert.Equal(t, "bob@x.com", rows[1].EngineLowered)

	// The third column is the ENGINE's lowercase, asked of the engine. Computing it here instead
	// would answer with the engine that is running rather than about it, and the pre-flight's
	// whole question is where the engine and strings.ToLower disagree.
	require.Len(t, d.statements, 1)
	assert.Contains(t, d.statements[0], "LOWER(email)")
}

func TestScanEmailCase_AnEmptyTableIsNoRowsAndNoError(t *testing.T) {
	d := &scriptedDriver{rows: []*scriptedRows{{cols: emailCaseColumns}}}
	db := scriptedDB(t, d)

	rows, err := db.ScanEmailCase()

	require.NoError(t, err)
	assert.Empty(t, rows)
}

// errStorage stands in for whatever the engine or the connection answered with. It is matched
// with errors.Is, so these cases say nothing about any driver's error type; what they hold is
// that the failure reaches the caller at all.
var errStorage = errors.New("the connection to the database was lost")

func TestScanEmailCase_ReturnsTheQueryFailureRatherThanAnEmptyTable(t *testing.T) {
	d := &scriptedDriver{rows: []*scriptedRows{{openErr: errStorage}}}
	db := scriptedDB(t, d)

	rows, err := db.ScanEmailCase()

	require.Error(t, err)
	assert.ErrorIs(t, err, errStorage, "the sentinel must stay discoverable through the wrapping")
	assert.Nil(t, rows, "a refused query must not read as a table with nothing in it")
}

func TestScanEmailCase_ReturnsAScanFailureRatherThanSkippingTheRow(t *testing.T) {
	// An id that is not a number: the shape a column type changing under the query produces,
	// and the one row the pre-flight would then never compare against any other.
	d := &scriptedDriver{rows: []*scriptedRows{{
		cols: emailCaseColumns,
		values: [][]driver.Value{
			{int64(1), "Alice@x.com", "alice@x.com"},
			{[]byte("not-a-number"), "alice@x.com", "alice@x.com"},
		},
	}}}
	db := scriptedDB(t, d)

	rows, err := db.ScanEmailCase()

	require.Error(t, err)
	assert.Contains(t, err.Error(), "unable to scan a user email")
	assert.Nil(t, rows, "a row that would not scan must not leave the rows around it looking complete")
}

func TestScanEmailCase_ReturnsAnIterationFailureRatherThanThePartialRead(t *testing.T) {
	// Two rows arrive and the result set then dies, which is what a dropped connection or a
	// server-side timeout looks like part way through a read. sql.Rows reports it through Err()
	// after Next() returns false, so this is the exit whose absence is invisible: without the
	// check the caller is handed the two rows as if they were the whole table.
	d := &scriptedDriver{rows: []*scriptedRows{{
		cols: emailCaseColumns,
		values: [][]driver.Value{
			{int64(1), "Alice@x.com", "alice@x.com"},
			{int64(2), "bob@x.com", "bob@x.com"},
		},
		failAt: 2,
		err:    errStorage,
	}}}
	db := scriptedDB(t, d)

	rows, err := db.ScanEmailCase()

	require.Error(t, err)
	assert.ErrorIs(t, err, errStorage)
	assert.Nil(t, rows, "a truncated read must not be answered as the whole table")
}
