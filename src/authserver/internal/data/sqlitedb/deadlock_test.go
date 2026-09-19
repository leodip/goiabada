package sqlitedb

import (
	"database/sql"
	"errors"
	"testing"

	mysqldriver "github.com/go-sql-driver/mysql"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/leodip/goiabada/core/errs"
	mssql "github.com/microsoft/go-mssqldb"
	sqlitedriver "modernc.org/sqlite"
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

// TestIsUniqueViolation is SQLite's row of the unique-key classifier table WrapSQLError consults.
//
// Unlike TestIsDeadlock above, this row has true entries: SQLite has one connection and so cannot
// deadlock, but it refuses a duplicate key exactly as the other three engines do.
//
// The driver's errors here are produced by the engine rather than constructed, because
// modernc.org/sqlite's Error keeps both of its fields unexported and exports no constructor. That
// is the stronger evidence anyway: these are the codes SQLite actually returns for these
// statements, not the codes this test believes it returns.
//
// The case that matters most is SQLITE_CONSTRAINT_NOTNULL. All of the refusals below are extended
// codes over the same primary code, SQLITE_CONSTRAINT (19), so a classifier written against the
// primary code would report a missing required field as a lost race for a key, and the API above
// would answer 409 to a caller whose request can never succeed (#279).
func TestIsUniqueViolation(t *testing.T) {
	unique := realSQLiteError(t,
		"CREATE TABLE t (email TEXT)",
		"CREATE UNIQUE INDEX idx_t_email ON t (email)",
		"INSERT INTO t (email) VALUES ('a@b')",
		"INSERT INTO t (email) VALUES ('a@b')")

	for _, tc := range []struct {
		name string
		err  error
		want bool
	}{
		{"the driver's unique violation, as modernc.org/sqlite returns it", unique, true},
		{"the same error wrapped once, as WrapSQLError returns it", errs.Wrap(unique, "unable to execute SQL"), true},
		{"the same error wrapped by the standard library", errors.Join(unique), true},
		{"the same error at the depth a handler sees it", errs.Wrap(errs.Wrap(unique, "unable to execute SQL"), "unable to insert user"), true},
		{"SQLITE_CONSTRAINT_PRIMARYKEY: an integer primary key", realSQLiteError(t,
			"CREATE TABLE t (id INTEGER PRIMARY KEY, v TEXT)",
			"INSERT INTO t (id, v) VALUES (1, 'a')",
			"INSERT INTO t (id, v) VALUES (1, 'b')"), true},
		{"SQLITE_CONSTRAINT_PRIMARYKEY: a composite primary key", realSQLiteError(t,
			"CREATE TABLE t (a INTEGER, b INTEGER, PRIMARY KEY (a, b))",
			"INSERT INTO t (a, b) VALUES (1, 2)",
			"INSERT INTO t (a, b) VALUES (1, 2)"), true},
		{"SQLITE_CONSTRAINT_ROWID: an explicitly supplied rowid that is taken", realSQLiteError(t,
			"CREATE TABLE t (v TEXT)",
			"INSERT INTO t (rowid, v) VALUES (1, 'a')",
			"INSERT INTO t (rowid, v) VALUES (1, 'b')"), true},
		{"SQLITE_CONSTRAINT_NOTNULL: a refusal a retry cannot fix", realSQLiteError(t,
			"CREATE TABLE t (v TEXT NOT NULL)",
			"INSERT INTO t (v) VALUES (NULL)"), false},
		{"SQLITE_CONSTRAINT_CHECK", realSQLiteError(t,
			"CREATE TABLE t (n INTEGER CHECK (n > 0))",
			"INSERT INTO t (n) VALUES (0)"), false},
		{"SQLITE_CONSTRAINT_FOREIGNKEY", realSQLiteError(t,
			"PRAGMA foreign_keys = ON",
			"CREATE TABLE parent (id INTEGER PRIMARY KEY)",
			"CREATE TABLE child (parent_id INTEGER REFERENCES parent (id))",
			"INSERT INTO child (parent_id) VALUES (99)"), false},
		{"a syntax error from the same driver", realSQLiteError(t, "SLECT 1"), false},
		{"sql.ErrNoRows", sql.ErrNoRows, false},
		{"nil", nil, false},
		{"a plain error carrying the engine's own sentence", errors.New("UNIQUE constraint failed: users.email"), false},
		{"MySQL's duplicate entry, another engine's error", &mysqldriver.MySQLError{Number: 1062}, false},
		{"PostgreSQL's unique violation, another engine's error", &pgconn.PgError{Code: "23505"}, false},
		{"SQL Server's unique constraint, by value", mssql.Error{Number: 2627}, false},
		{"SQL Server's unique index, by pointer", &mssql.Error{Number: 2601}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := isUniqueViolation(tc.err); got != tc.want {
				t.Errorf("isUniqueViolation(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}

// TestIsUniqueViolation_TheErrorsAreTheDriversOwn is the guard on the helper above. Every true and
// every constraint row of that table is only worth its assertion if the value really is a
// *sqlite.Error carrying the code the row claims; a helper that quietly returned a plain error
// would leave the whole table passing for the wrong reason.
func TestIsUniqueViolation_TheErrorsAreTheDriversOwn(t *testing.T) {
	unique := realSQLiteError(t,
		"CREATE TABLE t (email TEXT UNIQUE)",
		"INSERT INTO t (email) VALUES ('a@b')",
		"INSERT INTO t (email) VALUES ('a@b')")

	var sqliteErr *sqlitedriver.Error
	if !errors.As(unique, &sqliteErr) {
		t.Fatalf("the engine returned %T, not *sqlite.Error: %v", unique, unique)
	}
	if sqliteErr.Code() != sqliteConstraintUnique {
		t.Errorf("SQLITE_CONSTRAINT_UNIQUE = %d, want %d (the classifier reads this)",
			sqliteErr.Code(), sqliteConstraintUnique)
	}
}

// realSQLiteError runs stmts against a fresh in-memory database and returns the error the first
// failing one produced, failing the test when they all succeed.
func realSQLiteError(t *testing.T, stmts ...string) error {
	t.Helper()

	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("unable to open an in-memory database: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	for _, stmt := range stmts {
		if _, err := db.Exec(stmt); err != nil {
			return err
		}
	}
	t.Fatalf("every statement succeeded, so there is no driver error to classify: %v", stmts)
	return nil
}
