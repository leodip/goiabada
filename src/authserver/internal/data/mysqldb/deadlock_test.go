package mysqldb

import (
	"database/sql"
	"errors"
	"testing"

	mysqldriver "github.com/go-sql-driver/mysql"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/leodip/goiabada/core/errs"
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
		{"the same error wrapped once, as ExecSql returns it", errs.Wrap(deadlock, "unable to execute SQL"), true},
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

// TestIsUniqueViolation is MySQL's row of the unique-key classifier table WrapSQLError consults.
//
// One number covers every kind of key here: probe/constraint_codes.out recorded ER_DUP_ENTRY 1062
// for a CREATE UNIQUE INDEX, for a UNIQUE column constraint and for a PRIMARY KEY alike, which is
// why this table needs none of the extra codes SQLite's does.
//
// The cases that matter most are 1048 and 3819. Both are the engine refusing a write for a
// constraint, both arrive at the same call site, and neither can be fixed by trying again: a caller
// answering 409 to one of those would be telling the client to retry a request that can never
// succeed. Their numbers are the probe's too, not remembered ones (#279).
func TestIsUniqueViolation(t *testing.T) {
	duplicate := &mysqldriver.MySQLError{Number: 1062, Message: "Duplicate entry 'a@b' for key 'users.idx_email'"}

	for _, tc := range []struct {
		name string
		err  error
		want bool
	}{
		{"the driver's duplicate entry, as go-sql-driver returns it", duplicate, true},
		{"the same error wrapped once, as WrapSQLError returns it", errs.Wrap(duplicate, "unable to execute SQL"), true},
		{"the same error wrapped by the standard library", errors.Join(duplicate), true},
		{"the same error at the depth a handler sees it", errs.Wrap(errs.Wrap(duplicate, "unable to execute SQL"), "unable to insert user"), true},
		{"a primary-key collision, which this engine also numbers 1062", &mysqldriver.MySQLError{Number: 1062, Message: "Duplicate entry '1' for key 'zzc.PRIMARY'"}, true},
		{"1048 ER_BAD_NULL_ERROR: a constraint a retry cannot satisfy", &mysqldriver.MySQLError{Number: 1048, Message: "Column 'v' cannot be null"}, false},
		{"3819 ER_CHECK_CONSTRAINT_VIOLATED: likewise", &mysqldriver.MySQLError{Number: 3819, Message: "Check constraint 'zzc_chk_1' is violated."}, false},
		{"1213 this engine's own deadlock", &mysqldriver.MySQLError{Number: 1213}, false},
		{"a syntax error from the same driver", &mysqldriver.MySQLError{Number: 1064, Message: "You have an error in your SQL syntax"}, false},
		{"sql.ErrNoRows", sql.ErrNoRows, false},
		{"nil", nil, false},
		{"a plain error carrying the engine's own sentence", errors.New("Duplicate entry 'a@b' for key 'users.idx_email'"), false},
		{"PostgreSQL's unique violation, another engine's error", &pgconn.PgError{Code: "23505"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := isUniqueViolation(tc.err); got != tc.want {
				t.Errorf("isUniqueViolation(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}
