package migrator

import (
	"context"
	"database/sql"
	"fmt"
	"hash/crc32"
	"strconv"
	"strings"
	"sync"

	"github.com/leodip/goiabada/core/errs"
)

// advisoryLockIDSalt is golang-migrate's own salt, copied from its database/util.go. It is not a
// magic number we chose and it must not be changed: see advisoryLockID (#268).
const advisoryLockIDSalt uint32 = 1486364155

// advisoryLockID derives the lock resource name from the database name and whatever extra parts
// an engine's driver mixed in. It is a byte-for-byte copy of golang-migrate's
// database.GenerateAdvisoryLockId, and the value it produces is an INTER-PROCESS CONTRACT rather
// than an implementation detail.
//
// Two Goiabada processes exclude each other during a migration only if they compute the same
// name. During an upgrade one replica runs the previous release, which computes this name with
// golang-migrate, and another runs this one. Change the formula, the salt or the order the parts
// are joined in and the two releases take different locks, which means both migrate the same
// database at the same time, each seeing a clean version row the other is about to overwrite.
// The values this produces for Goiabada's own database names are pinned by a unit test (#268).
func advisoryLockID(name string, extra ...string) string {
	if len(extra) > 0 {
		name = strings.Join(append(extra, name), "\x00")
	}
	sum := crc32.ChecksumIEEE([]byte(name))
	sum = sum * advisoryLockIDSalt
	return strconv.FormatUint(uint64(sum), 10)
}

// migrationsTable is the name every engine's version table has. golang-migrate made it
// configurable and Goiabada never configured it, but it is part of two lock resource names, so it
// is spelled once here.
const migrationsTable = "schema_migrations"

// sqliteMigrationMu serialises migrations across every SQLite migrator in this process.
//
// SQLite is the one engine with no session-scoped lock statement, so golang-migrate's driver held
// nothing but a per-instance flag. Cross-process exclusion on a SQLite database is the file lock
// the engine itself takes; what is left for the runner is the in-process case, and one mutex for
// the process covers it without needing to decide whether two DSNs name the same file.
//
// ceiling: process-wide rather than per database file, so two SQLite migrations in one process
// run one after the other even when they touch different files. Revisit when a caller migrates
// several SQLite databases concurrently and the serialisation shows up as wall clock; keying the
// mutex by resolved file path is the next shape (#268).
var sqliteMigrationMu sync.Mutex

// Engine is the per-engine half of the runner: the handful of places where four engines that
// otherwise run the same SQL genuinely differ.
type Engine struct {
	// name is what refusals call this engine, and it matches the flavour names used elsewhere in
	// the data layer.
	name string

	// txWrap says whether a migration file runs inside a transaction the runner opens. SQLite
	// yes, the other three no, exactly as golang-migrate's drivers did. Migrations depend on it:
	// SQLite's 000039 and 000043 are written around the wrapper (PRAGMA foreign_keys is a no-op
	// inside a transaction), and SQL Server's 000040 opens its own BEGIN TRANSACTION with
	// SET XACT_ABORT ON, which an outer transaction would break.
	txWrap bool

	// placeholder renders the i-th (1-based) bind marker for this engine's driver. Only the
	// bookkeeping INSERT is parameterised; migration files run with no arguments at all.
	placeholder func(i int) string

	// lock and unlock take and release the cross-process migration lock on one connection. Both
	// are nil on SQLite, which takes sqliteMigrationMu instead.
	lock   func(ctx context.Context, conn *sql.Conn) error
	unlock func(ctx context.Context, conn *sql.Conn) error
}

// Name is the engine's name, as it appears in a refusal.
func (e Engine) Name() string { return e.name }

// Lock takes this engine's cross-process migration lock on conn, and Unlock releases it. They
// are the same statements on the same resource the runner itself uses, exported for the one
// caller outside this package that has to hold that exact resource: SQL Server's
// schema_migrations pre-create, which is a check followed by a create and is safe only while the
// migration lock is held (#293).
//
// Both are no-ops on SQLite, which has no session-scoped lock statement at all; the runner
// excludes itself there with sqliteMigrationMu, which run takes and this pair cannot, since a
// mutex has to be released by the goroutine that took it and these are two calls.
//
// The lock is scoped to the SESSION, so both must be issued on one *sql.Conn pinned out of the
// pool. Against a pooled *sql.DB the release can land on a different session and leave the lock
// held for the life of the process, blocking every later migrator on the database.
func (e Engine) Lock(ctx context.Context, conn *sql.Conn) error {
	if e.lock == nil {
		return nil
	}
	return e.lock(ctx, conn)
}

// Unlock releases what Lock took, on the same connection. See Lock.
func (e Engine) Unlock(ctx context.Context, conn *sql.Conn) error {
	if e.unlock == nil {
		return nil
	}
	return e.unlock(ctx, conn)
}

func questionMark(int) string { return "?" }

// SQLite has no lock statement and no transaction to sit inside, since the runner opens one
// around every file itself.
func SQLite() Engine {
	return Engine{
		name:        "sqlite",
		txWrap:      true,
		placeholder: questionMark,
	}
}

// MySQL locks with GET_LOCK, the one lock in the four with a timeout: ten seconds, then
// ErrLocked. The resource name is "<database>:schema_migrations", which is what
// golang-migrate's MySQL driver passed.
func MySQL(dbName string) Engine {
	resource := advisoryLockID(fmt.Sprintf("%s:%s", dbName, migrationsTable))
	return Engine{
		name:        "mysql",
		txWrap:      false,
		placeholder: questionMark,
		lock: func(ctx context.Context, conn *sql.Conn) error {
			var acquired sql.NullBool
			if err := conn.QueryRowContext(ctx, "SELECT GET_LOCK(?, 10)", resource).Scan(&acquired); err != nil {
				return errs.Errorf("unable to take the migration lock: %w", err)
			}
			if !acquired.Valid || !acquired.Bool {
				return ErrLocked
			}
			return nil
		},
		unlock: func(ctx context.Context, conn *sql.Conn) error {
			// RELEASE_LOCK answers 1 when this session held the lock, 0 when another session
			// holds it and NULL when no such lock exists. This session took it a moment ago on
			// this same connection, so anything but 1 means the lock did not come back.
			var released sql.NullBool
			if err := conn.QueryRowContext(ctx, "SELECT RELEASE_LOCK(?)", resource).Scan(&released); err != nil {
				return errs.Errorf("unable to release the migration lock: %w", err)
			}
			if !released.Valid || !released.Bool {
				return errs.Errorf("the migration lock was not released: RELEASE_LOCK answered %v", nullBoolString(released))
			}
			return nil
		},
	}
}

// Postgres locks with pg_advisory_lock, which waits indefinitely. The resource name mixes in the
// schema the migrations table lives in, resolved on the connection, because that is what
// golang-migrate's PostgreSQL driver did.
func Postgres(dbName string) Engine {
	resource := func(ctx context.Context, conn *sql.Conn) (string, error) {
		var schema string
		if err := conn.QueryRowContext(ctx, "SELECT CURRENT_SCHEMA()").Scan(&schema); err != nil {
			return "", errs.Errorf("unable to read the current schema: %w", err)
		}
		return advisoryLockID(dbName, schema, migrationsTable), nil
	}
	return Engine{
		name:        "postgres",
		txWrap:      false,
		placeholder: func(i int) string { return "$" + strconv.Itoa(i) },
		lock: func(ctx context.Context, conn *sql.Conn) error {
			id, err := resource(ctx, conn)
			if err != nil {
				return err
			}
			if _, err := conn.ExecContext(ctx, "SELECT pg_advisory_lock($1)", id); err != nil {
				return errs.Errorf("unable to take the migration lock: %w", err)
			}
			return nil
		},
		unlock: func(ctx context.Context, conn *sql.Conn) error {
			id, err := resource(ctx, conn)
			if err != nil {
				return err
			}
			// pg_advisory_unlock answers false rather than erroring when the session does not
			// hold the lock, which golang-migrate discarded by running this through Exec. A
			// session that still holds an advisory lock blocks every other migrator on this
			// database indefinitely, so it is read.
			var released sql.NullBool
			if err := conn.QueryRowContext(ctx, "SELECT pg_advisory_unlock($1)", id).Scan(&released); err != nil {
				return errs.Errorf("unable to release the migration lock: %w", err)
			}
			if !released.Valid || !released.Bool {
				return errs.Errorf("the migration lock was not released: pg_advisory_unlock answered %v", nullBoolString(released))
			}
			return nil
		},
	}
}

// SQLServer locks with sp_getapplock at LockOwner='Session', which waits indefinitely
// (LockTimeout = -1). The resource name mixes in the schema, resolved on the connection.
func SQLServer(dbName string) Engine {
	resource := func(ctx context.Context, conn *sql.Conn) (string, error) {
		var schema string
		if err := conn.QueryRowContext(ctx, "SELECT SCHEMA_NAME()").Scan(&schema); err != nil {
			return "", errs.Errorf("unable to read the current schema: %w", err)
		}
		return advisoryLockID(dbName, schema), nil
	}
	return Engine{
		name:        "sqlserver",
		txWrap:      false,
		placeholder: func(i int) string { return "@p" + strconv.Itoa(i) },
		lock: func(ctx context.Context, conn *sql.Conn) error {
			id, err := resource(ctx, conn)
			if err != nil {
				return err
			}
			const query = `
		DECLARE @lockResult int;
		EXEC @lockResult = sp_getapplock @Resource = @p1, @LockMode = 'Exclusive', @LockOwner = 'Session', @LockTimeout = -1;
		SELECT @lockResult;`
			var status int
			if err := conn.QueryRowContext(ctx, query, id).Scan(&status); err != nil {
				return errs.Errorf("unable to take the migration lock: %w", err)
			}
			// sp_getapplock answers 0 when the lock was granted and 1 when it was granted after
			// waiting; every negative value is a failure, and -1 is the timeout this call cannot
			// reach with LockTimeout = -1.
			if status < 0 {
				return errs.Errorf("unable to take the migration lock: sp_getapplock answered %d", status)
			}
			return nil
		},
		unlock: func(ctx context.Context, conn *sql.Conn) error {
			id, err := resource(ctx, conn)
			if err != nil {
				return err
			}
			// sp_releaseapplock raises an error rather than answering a code when the session
			// does not hold the lock, so the Exec error is the whole signal here.
			if _, err := conn.ExecContext(ctx,
				`EXEC sp_releaseapplock @Resource = @p1, @LockOwner = 'Session'`, id); err != nil {
				return errs.Errorf("the migration lock was not released: %w", err)
			}
			return nil
		},
	}
}

func nullBoolString(b sql.NullBool) string {
	if !b.Valid {
		return "NULL"
	}
	return strconv.FormatBool(b.Bool)
}
