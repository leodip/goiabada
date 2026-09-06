package mssqldb

import (
	"database/sql"
	"errors"
	"testing"

	mysqldriver "github.com/go-sql-driver/mysql"
	mssql "github.com/microsoft/go-mssqldb"
	pkgerrors "github.com/pkg/errors"
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
		{"the value wrapped once, as ExecSql returns it", pkgerrors.Wrap(deadlock, "unable to execute SQL"), true},
		{"the pointer wrapped once", pkgerrors.Wrap(&deadlock, "unable to execute SQL"), true},
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
