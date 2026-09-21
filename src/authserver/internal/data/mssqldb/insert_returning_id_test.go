package mssqldb

import (
	"strings"
	"testing"

	"github.com/huandu/go-sqlbuilder"
)

// TestInsertReturningIdSQL_SplicesTheClauseBeforeValues is SQL Server's half of the hook, checked
// against a statement sqlbuilder actually built. OUTPUT belongs between the column list and
// VALUES, and only the real builder's output says where that is.
func TestInsertReturningIdSQL_SplicesTheClauseBeforeValues(t *testing.T) {
	insertBuilder := sqlbuilder.SQLServer.NewInsertBuilder()
	insertBuilder.InsertInto("clients")
	insertBuilder.Cols("client_identifier", "enabled")
	insertBuilder.Values("probe", true)
	built, args := insertBuilder.Build()

	got, err := insertReturningIdSQL(built)
	if err != nil {
		t.Fatalf("insertReturningIdSQL returned %v, want nil", err)
	}

	if !strings.Contains(got, "OUTPUT INSERTED.id VALUES") {
		t.Errorf("the clause did not land in front of VALUES: %q", got)
	}
	// Ahead of VALUES and behind the column list, which is the only position SQL Server's
	// grammar accepts. Asserting on the substring alone would pass for a clause appended at
	// the end of a statement that happened to contain the word.
	if strings.Index(got, "OUTPUT INSERTED.id") > strings.Index(got, "VALUES") {
		t.Errorf("the clause landed after VALUES: %q", got)
	}
	// The placeholders are what the argument list was built against, so a rewrite that
	// disturbed them would bind the wrong values.
	if strings.Count(got, "@p") != len(args) {
		t.Errorf("the statement carries %d placeholder(s) for %d argument(s): %q",
			strings.Count(got, "@p"), len(args), got)
	}
}

// TestInsertReturningIdSQL_RefusesAStatementItCannotSplit is the guard that existed twenty-five
// times over and was unreachable from any test until the copies collapsed onto one function.
//
// It is not decoration. A statement with no VALUES to split on would otherwise go to the engine
// with no OUTPUT clause, succeed, answer no rows, and leave the caller storing id 0 over a row
// that exists.
func TestInsertReturningIdSQL_RefusesAStatementItCannotSplit(t *testing.T) {
	got, err := insertReturningIdSQL("INSERT INTO clients SELECT * FROM staging_clients")
	if err == nil {
		t.Fatalf("a statement with no VALUES clause was rewritten to %q instead of refused", got)
	}
	if got != "" {
		t.Errorf("a refused rewrite returned %q; it must return no statement at all", got)
	}
	if !strings.Contains(err.Error(), "unexpected SQL format from sqlbuilder") {
		t.Errorf("err = %q, want it to name the unrecognised statement", err.Error())
	}
}

// TestInsertReturningIdSQL_SplitsOnTheFirstValuesOnly pins the SplitN bound. An INSERT whose
// values themselves contained the word could otherwise be cut in two places; every value is a
// placeholder by the time this runs, so the case is theoretical, and the bound is what keeps it
// that way.
func TestInsertReturningIdSQL_SplitsOnTheFirstValuesOnly(t *testing.T) {
	got, err := insertReturningIdSQL("INSERT INTO t (a, b) VALUES (@p1, @p2) VALUES")
	if err != nil {
		t.Fatalf("insertReturningIdSQL returned %v, want nil", err)
	}
	if want := "INSERT INTO t (a, b) OUTPUT INSERTED.id VALUES (@p1, @p2) VALUES"; got != want {
		t.Errorf("insertReturningIdSQL = %q, want %q", got, want)
	}
}
