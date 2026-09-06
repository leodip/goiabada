package mysqldb

import (
	"database/sql"
	"errors"
	"testing"

	mysqldriver "github.com/go-sql-driver/mysql"
	"github.com/jackc/pgx/v5/pgconn"
	pkgerrors "github.com/pkg/errors"
)

// TestIsDeadlock is MySQL's row of the classifier table RunInTransaction consults. The case
// that matters most is 1205, ER_LOCK_WAIT_TIMEOUT: it is the number SQL Server uses for a
// DEADLOCK, so a classifier written from memory of the other engine retries every lock-wait
// timeout on this one, against a row somebody still holds (#301).
//
// mysql.MySQLError has pointer receivers, so the pointer is the only form that is an error and
// the only form the driver returns; there is no value form to check.
func TestIsDeadlock(t *testing.T) {
	deadlock := &mysqldriver.MySQLError{Number: 1213, Message: "Deadlock found when trying to get lock; try restarting transaction"}

	for _, tc := range []struct {
		name string
		err  error
		want bool
	}{
		{"the driver's deadlock, as go-sql-driver returns it", deadlock, true},
		{"the same error wrapped once, as ExecSql returns it", pkgerrors.Wrap(deadlock, "unable to execute SQL"), true},
		{"the same error wrapped by the standard library", errors.Join(deadlock), true},
		{"1205 ER_LOCK_WAIT_TIMEOUT: a lock wait that ran out, not a broken cycle", &mysqldriver.MySQLError{Number: 1205}, false},
		{"a syntax error from the same driver", &mysqldriver.MySQLError{Number: 1064, Message: "You have an error in your SQL syntax"}, false},
		{"sql.ErrNoRows", sql.ErrNoRows, false},
		{"nil", nil, false},
		{"a plain error", errors.New("Deadlock found when trying to get lock"), false},
		{"PostgreSQL's deadlock, another engine's error", &pgconn.PgError{Code: "40P01"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := isDeadlock(tc.err); got != tc.want {
				t.Errorf("isDeadlock(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}
