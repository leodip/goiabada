package sqlitedb

import (
	"database/sql"
	"errors"
	"testing"

	mysqldriver "github.com/go-sql-driver/mysql"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/leodip/goiabada/core/errs"
	mssql "github.com/microsoft/go-mssqldb"
)

// TestIsDeadlock is SQLite's row of the classifier table RunInTransaction consults, and every
// entry is false: the pool has one connection, so no two transactions of this process overlap
// and there is no cycle for the engine to break. The other engines' deadlock errors are in the
// table so that a future classifier here cannot be written by matching a number it has seen on
// another engine (#301).
func TestIsDeadlock(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
	}{
		{"nil", nil},
		{"sql.ErrNoRows", sql.ErrNoRows},
		{"a plain error", errors.New("database is locked")},
		{"a wrapped plain error", errs.Wrap(errors.New("database is locked"), "unable to execute SQL")},
		{"PostgreSQL's deadlock", &pgconn.PgError{Code: "40P01"}},
		{"MySQL's deadlock", &mysqldriver.MySQLError{Number: 1213}},
		{"SQL Server's deadlock, by value", mssql.Error{Number: 1205}},
		{"SQL Server's deadlock, by pointer", &mssql.Error{Number: 1205}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if isDeadlock(tc.err) {
				t.Errorf("isDeadlock(%v) = true on SQLite, which cannot deadlock", tc.err)
			}
		})
	}
}
