package postgresdb

import (
	"database/sql"
	"errors"
	"testing"

	mysqldriver "github.com/go-sql-driver/mysql"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/leodip/goiabada/core/errs"
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
		{"the same error wrapped once, as ExecSql returns it", errs.Wrap(deadlock, "unable to execute SQL"), true},
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

// TestIsUniqueViolation is PostgreSQL's row of the unique-key classifier table WrapSQLError
// consults.
//
// One SQLSTATE covers every kind of key here: probe/constraint_codes.out recorded 23505 for a
// CREATE UNIQUE INDEX, a UNIQUE column constraint and a PRIMARY KEY alike.
//
// The cases that matter most are its three neighbours in class 23. not_null_violation, 23502,
// check_violation, 23514 and foreign_key_violation, 23503 are all the engine refusing a write for a
// constraint, they arrive at the same call site, and none can be fixed by trying again: a caller
// answering 409 to one of those would be telling the client to retry a request that can never
// succeed. A classifier written against the class rather than the code would do exactly that. The
// numbers are the probe's, not remembered ones (#279).
func TestIsUniqueViolation(t *testing.T) {
	duplicate := &pgconn.PgError{Code: "23505", Message: "duplicate key value violates unique constraint \"idx_email\"", ConstraintName: "idx_email"}

	for _, tc := range []struct {
		name string
		err  error
		want bool
	}{
		{"the driver's unique violation, as pgx returns it", duplicate, true},
		{"the same error wrapped once, as WrapSQLError returns it", errs.Wrap(duplicate, "unable to execute SQL"), true},
		{"the same error wrapped by the standard library", errors.Join(duplicate), true},
		{"the same error at the depth a handler sees it", errs.Wrap(errs.Wrap(duplicate, "unable to execute SQL"), "unable to insert user"), true},
		{"a primary-key collision, which this engine also spells 23505", &pgconn.PgError{Code: "23505", ConstraintName: "zzc_pkey"}, true},
		{"23502 not_null_violation: the same class, a constraint a retry cannot satisfy", &pgconn.PgError{Code: "23502"}, false},
		{"23514 check_violation: likewise", &pgconn.PgError{Code: "23514"}, false},
		{"23503 foreign_key_violation: likewise", &pgconn.PgError{Code: "23503"}, false},
		{"42P04 duplicate_database: this file's other classifier's code", &pgconn.PgError{Code: "42P04"}, false},
		{"40P01 this engine's own deadlock", &pgconn.PgError{Code: "40P01"}, false},
		{"a syntax error from the same driver", &pgconn.PgError{Code: "42601", Message: "syntax error at or near"}, false},
		{"sql.ErrNoRows", sql.ErrNoRows, false},
		{"nil", nil, false},
		{"a plain error carrying the engine's own sentence", errors.New("duplicate key value violates unique constraint"), false},
		{"MySQL's duplicate entry, another engine's error", &mysqldriver.MySQLError{Number: 1062}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := isUniqueViolation(tc.err); got != tc.want {
				t.Errorf("isUniqueViolation(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}

// TestIsDuplicateDatabase covers the other classifier this file gained, the one that replaced a
// strings.Contains for "already exists" on the driver's English sentence.
//
// The row that matters is 23505. createDatabaseUnderAdvisoryLock's comment records what racing
// CREATE DATABASE statements actually do here: the losers fail with a unique violation on
// pg_database_datname_index, NOT with 42P04, which is why that create is serialised by an advisory
// lock. Tolerating 23505 as "the database is already there" would silently un-fix #293, since a
// loser would return success having created nothing (#279).
func TestIsDuplicateDatabase(t *testing.T) {
	duplicate := &pgconn.PgError{Code: "42P04", Message: "database \"goiabada\" already exists"}

	for _, tc := range []struct {
		name string
		err  error
		want bool
	}{
		{"the driver's duplicate database, as pgx returns it", duplicate, true},
		{"the same error wrapped once", errs.Wrap(duplicate, "unable to create database"), true},
		{"23505 on pg_database_datname_index: what a RACED create returns, and not this", &pgconn.PgError{Code: "23505", ConstraintName: "pg_database_datname_index"}, false},
		{"42501 insufficient_privilege: the create was refused, not redundant", &pgconn.PgError{Code: "42501"}, false},
		{"3D000 invalid_catalog_name", &pgconn.PgError{Code: "3D000"}, false},
		{"sql.ErrNoRows", sql.ErrNoRows, false},
		{"nil", nil, false},
		{"a plain error carrying the words the old text match looked for", errors.New("database \"goiabada\" already exists"), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := isDuplicateDatabase(tc.err); got != tc.want {
				t.Errorf("isDuplicateDatabase(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}
