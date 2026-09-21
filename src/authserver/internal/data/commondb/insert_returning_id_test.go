package commondb

import (
	"context"
	"database/sql/driver"
	"errors"
	"strings"
	"testing"

	"github.com/huandu/go-sqlbuilder"
)

// The two arms of insertReturningId, pinned at the scripted-driver seam.
//
// WHY THIS SEAM AND NOT ONLY THE DATA TIER. The data tier runs every Create* on all four engines
// and is what proves the arms are wired to the right engines; what it cannot ask for is a driver
// that refuses LastInsertId while a hook is absent, a result set that dies at row zero, or a
// value that fails to scan. Those are the three failures the fifty hand-written copies each
// carried their own version of, and they are the ones a collapse onto one helper can lose
// without any engine noticing (#416).
//
// The nouns are deliberately a made-up one, "widget": the messages are built from the argument,
// so a real table name would let a test pass by coincidence with the argument ignored.

// probeInsert is one built INSERT, minimal and independent of models. The SQLite flavor only
// decides the placeholder, which the scripted driver ignores.
func probeInsert() *sqlbuilder.InsertBuilder {
	insertBuilder := sqlbuilder.SQLite.NewInsertBuilder()
	insertBuilder.InsertInto("widgets")
	insertBuilder.Cols("name")
	insertBuilder.Values("probe")
	return insertBuilder
}

// appendReturningId is what postgresdb wires. It is spelled out here rather than imported so
// this package keeps no dependency on a dialect, and so the assertion below reads against a
// rewrite whose text the test itself chose.
func appendReturningId(insertSQL string) (string, error) {
	return insertSQL + " RETURNING id", nil
}

// TestInsertReturningId_LastInsertIdArm is the SQLite and MySQL path: no hook wired, the
// statement goes through ExecSql, and the id is whatever the driver reports.
func TestInsertReturningId_LastInsertIdArm(t *testing.T) {
	script := &scriptedDriver{execs: []*scriptedExec{{rowsAffected: 1, lastInsertId: 77}}}
	d := scriptedDB(t, script)

	id, err := d.insertReturningId(context.Background(), nil, probeInsert(), "widget")
	if err != nil {
		t.Fatalf("insertReturningId returned %v, want nil", err)
	}
	if id != 77 {
		t.Errorf("id = %d, want 77, which is what the driver reported", id)
	}

	if len(script.statements) != 1 {
		t.Fatalf("%d statement(s) reached the driver, want 1", len(script.statements))
	}
	// With no hook the statement must arrive exactly as sqlbuilder built it. A rewrite applied
	// unconditionally would be invalid SQL on the two engines that take this arm.
	if strings.Contains(script.statements[0], "RETURNING") {
		t.Errorf("statement was rewritten on the arm that has no hook: %q", script.statements[0])
	}
	if script.queryCount != 0 {
		t.Errorf("%d quer(ies) were run; this arm must not query at all", script.queryCount)
	}
}

// TestInsertReturningId_LastInsertIdArmReportsARefusingDriver is the #283 shape, made visible.
// pgx and go-mssqldb both answer LastInsertId with an error, so a Create* that reaches this arm
// on those engines fails loudly rather than storing id 0 -- which is why no lint is owed for a
// future Create* written without this helper: the data tier goes red on two of four engines.
func TestInsertReturningId_LastInsertIdArmReportsARefusingDriver(t *testing.T) {
	// No lastInsertId scripted, so the statement answers with driver.RowsAffected, whose
	// LastInsertId returns an error.
	d := scriptedDB(t, &scriptedDriver{execs: []*scriptedExec{{rowsAffected: 1}}})

	_, err := d.insertReturningId(context.Background(), nil, probeInsert(), "widget")
	if err == nil {
		t.Fatal("a driver that refuses LastInsertId was reported as a successful insert")
	}
	if !strings.Contains(err.Error(), "unable to get last insert id") {
		t.Errorf("err = %q, want it to name the id read", err.Error())
	}
}

// TestInsertReturningId_LastInsertIdArmWrapsTheInsertFailure pins the message and the sentinel on
// the arm SQLite and MySQL take. The wrapping matters because the handler above asks errors.Is
// for ErrUniqueViolation to answer 409 rather than 500.
func TestInsertReturningId_LastInsertIdArmWrapsTheInsertFailure(t *testing.T) {
	driverErr := &driverUniqueError{msg: "UNIQUE constraint failed: widgets.name"}
	d := scriptedDB(t, &scriptedDriver{execs: []*scriptedExec{{err: driverErr}}})
	d.IsUniqueViolation = func(err error) bool {
		var target *driverUniqueError
		return errors.As(err, &target)
	}

	_, err := d.insertReturningId(context.Background(), nil, probeInsert(), "widget")
	if err == nil {
		t.Fatal("a refused statement was reported as a successful insert")
	}
	if !errors.Is(err, ErrUniqueViolation) {
		t.Errorf("errors.Is(err, ErrUniqueViolation) = false; err = %v", err)
	}
	want := "unable to insert widget: unable to execute SQL: unique constraint violation: " +
		"UNIQUE constraint failed: widgets.name"
	if err.Error() != want {
		t.Errorf("err.Error() = %q, want %q", err.Error(), want)
	}
}

// TestInsertReturningId_ReturningArm is the PostgreSQL and SQL Server path: the hook rewrites the
// statement, it is run as a query, and the id is scanned out of the one row it answers with.
func TestInsertReturningId_ReturningArm(t *testing.T) {
	script := &scriptedDriver{rows: []*scriptedRows{{
		cols:   []string{"id"},
		values: [][]driver.Value{{int64(42)}},
	}}}
	d := scriptedDB(t, script)
	d.InsertReturningIdSQL = appendReturningId

	id, err := d.insertReturningId(context.Background(), nil, probeInsert(), "widget")
	if err != nil {
		t.Fatalf("insertReturningId returned %v, want nil", err)
	}
	if id != 42 {
		t.Errorf("id = %d, want 42, which is the value the result set carried", id)
	}

	// The statement the ENGINE saw, not the one the builder made: a hook whose output were
	// dropped would leave every assertion above still passing on this driver, which answers
	// whatever it was scripted with regardless of the SQL.
	if len(script.statements) != 1 {
		t.Fatalf("%d statement(s) reached the driver, want 1", len(script.statements))
	}
	if !strings.HasSuffix(script.statements[0], " RETURNING id") {
		t.Errorf("the statement the engine ran was %q, which is not what the hook returned",
			script.statements[0])
	}
	if script.execCount != 0 {
		t.Errorf("%d statement(s) went through Exec; this arm must query", script.execCount)
	}
}

// TestInsertReturningId_ReturningArmSurfacesADeferredViolation is the one behaviour a careless
// collapse loses, and the reason WrapSQLError is reachable from here.
//
// pgx and go-mssqldb can report a constraint violation through the result set rather than from
// the query call, and then Next() simply reports no row. Without the rows.Err() check the insert
// reads as a success with id 0 and the sentinel is unreachable on exactly the two engines that
// take this arm.
func TestInsertReturningId_ReturningArmSurfacesADeferredViolation(t *testing.T) {
	driverErr := &driverUniqueError{msg: "duplicate key value violates unique constraint"}
	d := scriptedDB(t, &scriptedDriver{rows: []*scriptedRows{{
		cols:   []string{"id"},
		failAt: 0,
		err:    driverErr,
	}}})
	d.InsertReturningIdSQL = appendReturningId
	d.IsUniqueViolation = func(err error) bool {
		var target *driverUniqueError
		return errors.As(err, &target)
	}

	id, err := d.insertReturningId(context.Background(), nil, probeInsert(), "widget")
	if err == nil {
		t.Fatalf("a violation the driver deferred to the result set was reported as a "+
			"successful insert with id %d", id)
	}
	if !errors.Is(err, ErrUniqueViolation) {
		t.Errorf("errors.Is(err, ErrUniqueViolation) = false, so the handler above cannot "+
			"answer 409 on these two engines; err = %v", err)
	}
	if want := "unable to insert widget: unique constraint violation: " + driverErr.msg; err.Error() != want {
		t.Errorf("err.Error() = %q, want %q", err.Error(), want)
	}
}

// TestInsertReturningId_ReturningArmReportsAScanFailure keeps the second of the two messages the
// hand-written copies printed. It is the only failure whose text names the noun twice over.
func TestInsertReturningId_ReturningArmReportsAScanFailure(t *testing.T) {
	d := scriptedDB(t, &scriptedDriver{rows: []*scriptedRows{{
		cols:   []string{"id"},
		values: [][]driver.Value{{"not a number"}},
	}}})
	d.InsertReturningIdSQL = appendReturningId

	_, err := d.insertReturningId(context.Background(), nil, probeInsert(), "widget")
	if err == nil {
		t.Fatal("an unreadable id was reported as a successful insert")
	}
	if !strings.HasPrefix(err.Error(), "unable to scan widget id") {
		t.Errorf("err = %q, want it to open with the scan message naming the noun", err.Error())
	}
}

// TestInsertReturningId_ReturningArmOnAnEmptyResultSet records what today's code answers when the
// engine reports neither a row nor an error, which is id 0 and no error. It is not a shape any of
// the four engines produces for an INSERT, and it is what the fifty copies did; recorded here so
// that changing it is a decision rather than a side effect.
func TestInsertReturningId_ReturningArmOnAnEmptyResultSet(t *testing.T) {
	d := scriptedDB(t, &scriptedDriver{rows: []*scriptedRows{{cols: []string{"id"}}}})
	d.InsertReturningIdSQL = appendReturningId

	id, err := d.insertReturningId(context.Background(), nil, probeInsert(), "widget")
	if err != nil {
		t.Fatalf("insertReturningId returned %v, want nil", err)
	}
	if id != 0 {
		t.Errorf("id = %d, want 0", id)
	}
}

// TestInsertReturningId_AHookFailureStopsBeforeTheEngine is what makes mssqldb's refusal worth
// having. A statement it did not recognise must never reach the engine without its OUTPUT clause,
// because it would then succeed and answer no rows, and the caller would store id 0 over a row
// that exists.
func TestInsertReturningId_AHookFailureStopsBeforeTheEngine(t *testing.T) {
	refused := errors.New("unexpected SQL format from sqlbuilder")
	script := &scriptedDriver{}
	d := scriptedDB(t, script)
	d.InsertReturningIdSQL = func(string) (string, error) { return "", refused }

	_, err := d.insertReturningId(context.Background(), nil, probeInsert(), "widget")
	if !errors.Is(err, refused) {
		t.Errorf("err = %v, want the hook's own error unchanged", err)
	}
	if script.execCount != 0 || script.queryCount != 0 {
		t.Errorf("%d exec(s) and %d quer(ies) reached the engine; a rewrite that failed must "+
			"send nothing", script.execCount, script.queryCount)
	}
}

// TestInsertReturningId_ReturningArmWrapsARefusedQuery is the arm's other entry: the engine
// refused the statement outright rather than deferring anything.
func TestInsertReturningId_ReturningArmWrapsARefusedQuery(t *testing.T) {
	d := scriptedDB(t, &scriptedDriver{rows: []*scriptedRows{{
		openErr: errors.New("relation \"widgets\" does not exist"),
	}}})
	d.InsertReturningIdSQL = appendReturningId

	_, err := d.insertReturningId(context.Background(), nil, probeInsert(), "widget")
	if err == nil {
		t.Fatal("a refused query was reported as a successful insert")
	}
	want := "unable to insert widget: unable to execute SQL: relation \"widgets\" does not exist"
	if err.Error() != want {
		t.Errorf("err.Error() = %q, want %q", err.Error(), want)
	}
}
