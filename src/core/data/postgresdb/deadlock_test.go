package postgresdb

import (
	"database/sql"
	"errors"
	"testing"

	mysqldriver "github.com/go-sql-driver/mysql"
	"github.com/jackc/pgx/v5/pgconn"
	pkgerrors "github.com/pkg/errors"
)

// TestIsDeadlock is PostgreSQL's row of the classifier table RunInTransaction consults. The
// case that matters most is 55P03: a lock wait that ran out looks like a deadlock to a reader
// who remembers only that "the transaction failed on a lock", and rerunning it would wait the
// same timeout again against a row somebody still holds (#301).
//
// pgconn.PgError has pointer receivers, so the pointer is the only form that is an error and
// the only form the driver returns; there is no value form to check.
func TestIsDeadlock(t *testing.T) {
	deadlock := &pgconn.PgError{Code: "40P01", Message: "deadlock detected"}

	for _, tc := range []struct {
		name string
		err  error
		want bool
	}{
		{"the driver's deadlock, as pgx returns it", deadlock, true},
		{"the same error wrapped once, as ExecSql returns it", pkgerrors.Wrap(deadlock, "unable to execute SQL"), true},
		{"the same error wrapped by the standard library", errors.Join(deadlock), true},
		{"55P03 lock_not_available: a lock wait that ran out, not a broken cycle", &pgconn.PgError{Code: "55P03"}, false},
		{"a syntax error from the same driver", &pgconn.PgError{Code: "42601", Message: "syntax error at or near"}, false},
		{"sql.ErrNoRows", sql.ErrNoRows, false},
		{"nil", nil, false},
		{"a plain error", errors.New("deadlock detected"), false},
		{"MySQL's deadlock, another engine's error", &mysqldriver.MySQLError{Number: 1213}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := isDeadlock(tc.err); got != tc.want {
				t.Errorf("isDeadlock(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}
