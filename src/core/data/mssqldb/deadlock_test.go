package mssqldb

import (
	"database/sql"
	"errors"
	"testing"

	mysqldriver "github.com/go-sql-driver/mysql"
	"github.com/leodip/goiabada/core/errs"
	mssql "github.com/microsoft/go-mssqldb"
)

// TestIsDeadlock is SQL Server's row of the classifier table RunInTransaction consults.
//
// Two things are specific to this engine. mssql.Error has VALUE receivers, so both the value
// and the pointer are errors, the driver hands out one shape from one path and the other from
// another, and errors.As matches only the shape it was asked for: both rows are here because a
// classifier checking one form is right on the path that was tested and silent on the other.
// And 1205 means deadlock HERE while meaning lock-wait timeout on MySQL; SQL Server's lock-wait
// timeout is 1222, and it is not retried, because the row is still held (#301).
func TestIsDeadlock(t *testing.T) {
	deadlock := mssql.Error{Number: 1205, Message: "Transaction (Process ID 52) was deadlocked on lock resources with another process and has been chosen as the deadlock victim. Rerun the transaction."}

	for _, tc := range []struct {
		name string
		err  error
		want bool
	}{
		{"the driver's deadlock, by value", deadlock, true},
		{"the driver's deadlock, by pointer", &deadlock, true},
		{"the value wrapped once, as ExecSql returns it", errs.Wrap(deadlock, "unable to execute SQL"), true},
		{"the pointer wrapped once", errs.Wrap(&deadlock, "unable to execute SQL"), true},
		{"the value wrapped by the standard library", errors.Join(deadlock), true},
		{"1222 lock request time out period exceeded: a lock wait that ran out, not a broken cycle", mssql.Error{Number: 1222}, false},
		{"1222 by pointer", &mssql.Error{Number: 1222}, false},
		{"a syntax error from the same driver", mssql.Error{Number: 102, Message: "Incorrect syntax near"}, false},
		{"sql.ErrNoRows", sql.ErrNoRows, false},
		{"nil", nil, false},
		{"a plain error", errors.New("chosen as the deadlock victim"), false},
		{"MySQL's 1205, another engine's error carrying this engine's deadlock number", &mysqldriver.MySQLError{Number: 1205}, false},
		{"MySQL's deadlock, another engine's error", &mysqldriver.MySQLError{Number: 1213}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := isDeadlock(tc.err); got != tc.want {
				t.Errorf("isDeadlock(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}

// TestIsUniqueViolation is SQL Server's row of the unique-key classifier table WrapSQLError
// consults, and this engine is the one that needs two numbers.
//
// probe/constraint_codes.out recorded 2601, "Cannot insert duplicate key row ... with unique index",
// for a CREATE UNIQUE INDEX, and 2627, "Violation of UNIQUE KEY constraint", for a UNIQUE column
// constraint -- and 2627 again for a PRIMARY KEY. Goiabada's schema carries both shapes on this
// engine, so a classifier accepting one number is right on the tables that were tested and silent
// on the rest.
//
// The value/pointer rows are here for the reason TestIsDeadlock gives: mssql.Error has VALUE
// receivers, both forms are errors, and errors.As matches only the shape it was asked for.
//
// The cases that matter most are 515 and 547, the engine refusing a write for a NOT NULL and for a
// CHECK or FOREIGN KEY constraint. They arrive at the same call site and no retry can satisfy them,
// so answering 409 to one would tell the client to retry a request that can never succeed (#279).
func TestIsUniqueViolation(t *testing.T) {
	constraint := mssql.Error{Number: 2627, Message: "Violation of UNIQUE KEY constraint 'UQ__users__email'. Cannot insert duplicate key in object 'dbo.users'."}
	index := mssql.Error{Number: 2601, Message: "Cannot insert duplicate key row in object 'dbo.users' with unique index 'idx_email'."}

	for _, tc := range []struct {
		name string
		err  error
		want bool
	}{
		{"2627 a UNIQUE KEY constraint, by value", constraint, true},
		{"2627 by pointer", &constraint, true},
		{"2601 a unique index, by value", index, true},
		{"2601 by pointer", &index, true},
		{"2627 wrapped once, as WrapSQLError returns it", errs.Wrap(constraint, "unable to execute SQL"), true},
		{"2601 wrapped once", errs.Wrap(index, "unable to execute SQL"), true},
		{"2627 wrapped by the standard library", errors.Join(constraint), true},
		{"2601 at the depth a handler sees it", errs.Wrap(errs.Wrap(index, "unable to execute SQL"), "unable to insert user"), true},
		{"a primary-key collision, which this engine also numbers 2627", mssql.Error{Number: 2627, Message: "Violation of PRIMARY KEY constraint 'PK__zzc'."}, true},
		{"515 cannot insert NULL: a constraint a retry cannot satisfy", mssql.Error{Number: 515}, false},
		{"515 by pointer", &mssql.Error{Number: 515}, false},
		{"547 a CHECK or FOREIGN KEY conflict: likewise", mssql.Error{Number: 547}, false},
		{"1205 this engine's own deadlock", mssql.Error{Number: 1205}, false},
		{"a syntax error from the same driver", mssql.Error{Number: 102, Message: "Incorrect syntax near"}, false},
		{"sql.ErrNoRows", sql.ErrNoRows, false},
		{"nil", nil, false},
		{"a plain error carrying the engine's own sentence", errors.New("Violation of UNIQUE KEY constraint"), false},
		{"MySQL's duplicate entry, another engine's error", &mysqldriver.MySQLError{Number: 1062}, false},
		{"MySQL's 2601 has no meaning, but the type is another engine's", &mysqldriver.MySQLError{Number: 2601}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := isUniqueViolation(tc.err); got != tc.want {
				t.Errorf("isUniqueViolation(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}
