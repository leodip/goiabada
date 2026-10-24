package commondb

import (
	"context"
	"database/sql/driver"
	"errors"
	"strings"
	"testing"

	"github.com/leodip/goiabada/authserver/internal/data"
)

// The two arms of insert, pinned at the scripted-driver seam.
//
// WHY THIS SEAM AND NOT ONLY THE DATA TIER. The data tier runs every Create* on all four engines
// and is what proves each engine's INSERT answers its id the way its arm reads it; what it cannot
// ask for is a driver that refuses LastInsertId, a result set that dies at row zero, or a value
// that fails to scan. Those are the three failures the fifty hand-written copies each carried their
// own version of, and they are the ones a collapse onto one helper can lose without any engine
// noticing (#416).
//
// The nouns are deliberately a made-up one, "widget": the messages are built from the argument,
// so a real table name would let a test pass by coincidence with the argument ignored.

// widgetInsert is one INSERT in each engine's text, chosen by the test.
var widgetInsert = statement{
	sqlite:   "INSERT INTO widgets (name) VALUES (?)",
	mysql:    "INSERT INTO widgets (name) VALUES (?)",
	postgres: "INSERT INTO widgets (name) VALUES ($1) RETURNING id",
	mssql:    "INSERT INTO widgets (name) OUTPUT INSERTED.id VALUES (@p1)",
}

// TestInsert_EachEngineRunsItsOwnTextUnchanged is both arms on the engines that take them: SQLite
// and MySQL run the statement and read LastInsertId, PostgreSQL and SQL Server run it as a query
// and scan the id it answers with, and every engine receives its own version byte for byte, since
// nothing rewrites the text on its way to the driver (#644).
func TestInsert_EachEngineRunsItsOwnTextUnchanged(t *testing.T) {
	for _, dialect := range allDialects {
		t.Run(string(dialect), func(t *testing.T) {
			script := &scriptedDriver{
				execs: []*scriptedExec{{rowsAffected: 1, lastInsertId: 77}},
				rows:  []*scriptedRows{{cols: []string{"id"}, values: [][]driver.Value{{int64(77)}}}},
			}
			d := scriptedDBFor(t, script, dialect)

			id, err := d.insert(context.Background(), nil, widgetInsert, "widget", "probe")
			if err != nil {
				t.Fatalf("insert returned %v, want nil", err)
			}
			if id != 77 {
				t.Errorf("id = %d, want 77", id)
			}
			if len(script.statements) != 1 || script.statements[0] != widgetInsert.text(dialect) {
				t.Errorf("the engine ran %q, want exactly %q", script.statements, widgetInsert.text(dialect))
			}
			returnsARow := dialect == data.Postgres || dialect == data.MSSQL
			if returnsARow && (script.queryCount != 1 || script.execCount != 0) {
				t.Errorf("%s must run its insert as a query answering the id", dialect)
			}
			if !returnsARow && (script.execCount != 1 || script.queryCount != 0) {
				t.Errorf("%s must run its insert as a statement and read LastInsertId", dialect)
			}
		})
	}
}

// TestInsert_LastInsertIdArmReportsARefusingDriver is the #283 shape, made visible. pgx and
// go-mssqldb both answer LastInsertId with an error, so a Create* that reaches this arm on those
// engines fails loudly rather than storing id 0 -- which is why no lint is owed for a future
// Create* written without this helper: the data tier goes red on two of four engines.
func TestInsert_LastInsertIdArmReportsARefusingDriver(t *testing.T) {
	// No lastInsertId scripted, so the statement answers with driver.RowsAffected, whose
	// LastInsertId returns an error.
	d := scriptedDBFor(t, &scriptedDriver{execs: []*scriptedExec{{rowsAffected: 1}}}, data.SQLite)

	_, err := d.insert(context.Background(), nil, widgetInsert, "widget", "probe")
	if err == nil {
		t.Fatal("a driver that refuses LastInsertId was reported as a successful insert")
	}
	if !strings.Contains(err.Error(), "unable to get last insert id") {
		t.Errorf("err = %q, want it to name the id read", err.Error())
	}
}

// TestInsert_LastInsertIdArmWrapsTheInsertFailure pins the message and the sentinel on the arm
// SQLite and MySQL take. The wrapping matters because the handler above asks errors.Is for
// data.ErrUniqueViolation to answer 409 rather than 500.
func TestInsert_LastInsertIdArmWrapsTheInsertFailure(t *testing.T) {
	driverErr := &driverUniqueError{msg: "UNIQUE constraint failed: widgets.name"}
	d := scriptedDBFor(t, &scriptedDriver{execs: []*scriptedExec{{err: driverErr}}}, data.MySQL)
	d.IsUniqueViolation = func(err error) bool {
		var target *driverUniqueError
		return errors.As(err, &target)
	}

	_, err := d.insert(context.Background(), nil, widgetInsert, "widget", "probe")
	if err == nil {
		t.Fatal("a refused statement was reported as a successful insert")
	}
	if !errors.Is(err, data.ErrUniqueViolation) {
		t.Errorf("errors.Is(err, data.ErrUniqueViolation) = false; err = %v", err)
	}
	want := "unable to insert widget: unable to execute SQL: unique constraint violation: " +
		"UNIQUE constraint failed: widgets.name"
	if err.Error() != want {
		t.Errorf("err.Error() = %q, want %q", err.Error(), want)
	}
}

// TestInsert_AViolationDeferredToTheResultSetSurfaces is the one behaviour a careless collapse
// loses, and the reason wrapSQLError is reachable from here.
//
// pgx and go-mssqldb can report a constraint violation through the result set rather than from
// the query call, and then Next() simply reports no row. Without the rows.Err() check the insert
// reads as a success with id 0 and the sentinel is unreachable on exactly the two engines that
// take this arm.
func TestInsert_AViolationDeferredToTheResultSetSurfaces(t *testing.T) {
	for _, dialect := range []data.Dialect{data.Postgres, data.MSSQL} {
		t.Run(string(dialect), func(t *testing.T) {
			driverErr := &driverUniqueError{msg: "duplicate key value violates unique constraint"}
			d := scriptedDBFor(t, &scriptedDriver{rows: []*scriptedRows{{
				cols: []string{"id"}, failAt: 0, err: driverErr,
			}}}, dialect)
			d.IsUniqueViolation = func(err error) bool {
				var target *driverUniqueError
				return errors.As(err, &target)
			}

			id, err := d.insert(context.Background(), nil, widgetInsert, "widget", "probe")
			if err == nil {
				t.Fatalf("a violation the driver deferred to the result set was reported as a "+
					"successful insert with id %d", id)
			}
			if !errors.Is(err, data.ErrUniqueViolation) {
				t.Errorf("errors.Is(err, data.ErrUniqueViolation) = false, so the handler above "+
					"cannot answer 409 on this engine; err = %v", err)
			}
			if want := "unable to insert widget: unique constraint violation: " + driverErr.msg; err.Error() != want {
				t.Errorf("err.Error() = %q, want %q", err.Error(), want)
			}
		})
	}
}

// TestInsert_ReturningArmReportsAScanFailure keeps the second of the two messages the
// hand-written copies printed. It is the only failure whose text names the noun twice over.
func TestInsert_ReturningArmReportsAScanFailure(t *testing.T) {
	d := scriptedDBFor(t, &scriptedDriver{rows: []*scriptedRows{{
		cols:   []string{"id"},
		values: [][]driver.Value{{"not a number"}},
	}}}, data.Postgres)

	_, err := d.insert(context.Background(), nil, widgetInsert, "widget", "probe")
	if err == nil {
		t.Fatal("an unreadable id was reported as a successful insert")
	}
	if !strings.HasPrefix(err.Error(), "unable to scan widget id") {
		t.Errorf("err = %q, want it to open with the scan message naming the noun", err.Error())
	}
}

// TestInsert_ReturningArmOnAnEmptyResultSet records what the code answers when the engine reports
// neither a row nor an error, which is id 0 and no error. It is not a shape any of the four
// engines produces for an INSERT, and it is what the fifty copies did; recorded here so that
// changing it is a decision rather than a side effect.
func TestInsert_ReturningArmOnAnEmptyResultSet(t *testing.T) {
	d := scriptedDBFor(t, &scriptedDriver{rows: []*scriptedRows{{cols: []string{"id"}}}}, data.MSSQL)

	id, err := d.insert(context.Background(), nil, widgetInsert, "widget", "probe")
	if err != nil {
		t.Fatalf("insert returned %v, want nil", err)
	}
	if id != 0 {
		t.Errorf("id = %d, want 0", id)
	}
}

// TestInsert_ReturningArmWrapsARefusedQuery is the arm's other entry: the engine refused the
// statement outright rather than deferring anything.
func TestInsert_ReturningArmWrapsARefusedQuery(t *testing.T) {
	d := scriptedDBFor(t, &scriptedDriver{rows: []*scriptedRows{{
		openErr: errors.New("relation \"widgets\" does not exist"),
	}}}, data.Postgres)

	_, err := d.insert(context.Background(), nil, widgetInsert, "widget", "probe")
	if err == nil {
		t.Fatal("a refused query was reported as a successful insert")
	}
	want := "unable to insert widget: unable to execute SQL: relation \"widgets\" does not exist"
	if err.Error() != want {
		t.Errorf("err.Error() = %q, want %q", err.Error(), want)
	}
}
