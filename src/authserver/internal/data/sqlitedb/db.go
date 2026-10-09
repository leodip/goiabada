// Package sqlitedb is the SQLite adapter: the constructor that opens the operator's file, or the
// in-memory default, with the PRAGMAs Goiabada requires, the migration chain SQLite runs, and the
// handful of Database methods whose SQL differs from commondb's. Everything else is promoted from
// the embedded common implementation.
package sqlitedb

import (
	"context"
	"database/sql"
	"embed"
	"errors"
	"fmt"
	"log/slog"
	"strings"

	"github.com/huandu/go-sqlbuilder"
	"github.com/leodip/goiabada/authserver/internal/data"
	"github.com/leodip/goiabada/authserver/internal/data/commondb"
	"github.com/leodip/goiabada/authserver/internal/data/migrator"
	"github.com/leodip/goiabada/core/errs"
	sqlitedriver "modernc.org/sqlite"
)

//go:embed migrations/*.sql
var sqliteMigrationsFs embed.FS

// Database declares only the methods SQLite needs its own SQL for; the rest are promoted
// from the embedded common implementation. See commondb.Database for what embedding does
// and does not buy (#416).
type Database struct {
	*commondb.Database
}

// The compiler holds the adapter to the whole interface here, in its own package, so an engine
// missing a method fails where the method is missing rather than only where datafactory hands
// the adapter out (#438).
var _ data.Database = (*Database)(nil)

// Pool is SQLite's connection pool, whatever the GOIABADA_DB_* pool settings say: one connection,
// kept idle, never recycled. A function rather than a variable, so nothing can change it. One writer at a time is SQLite's own rule, and the single connection
// is what the comments in issuance, refresh-token rotation and commondb reason from, so the pool
// settings are not this engine's to apply (#394).
func Pool() data.PoolConfig {
	return data.PoolConfig{MaxOpenConns: 1, MaxIdleConns: 1}
}

// New opens the SQLite database dsn names, or a shared in-memory one when dsn is empty.
//
// The DSN is all SQLite reads, so it is all New takes. GOIABADA_DB_CREATE does not apply here:
// there is no create statement and no maintenance connection on SQLite, and what decides whether
// an absent file is created is the operator's own DSN. The equivalent is mode=rw in it, which the
// driver honours by refusing to create the file (#293, #438 decision 4), but only in a file: URI
// such as file:/data/goiabada.db?mode=rw: after a plain path, the setup wizard's form, the driver
// drops the query and creates the file all the same.
func New(ctx context.Context, dsn string, logSQL bool) (*Database, error) {
	if dsn == "" {
		dsn = "file::memory:?cache=shared"
	}

	// The effective dsn rather than the one passed in, which is empty on the default above: the
	// pair of records this replaces said "db dsn: " with nothing after it for every in-memory
	// start, which is the one case where a reader most needs to know which database was opened
	// (#320).
	slog.InfoContext(ctx, "using database", "type", "sqlite", "dsn", dsn)

	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, errs.Wrap(err, "unable to open database")
	}

	Pool().ApplyTo(db)

	// The ping comes before the PRAGMAs because the first statement on the pool is what opens
	// the file, so it is what an unopenable file fails: behind the PRAGMAs, an operator read
	// "failed to execute PRAGMA foreign_keys = ON" for a path that does not exist, and this
	// branch was unreachable for that input. errors.As rather than a type assertion, and the
	// driver's error kept in the chain with SQLite's own name for the code beside it, e.g.
	// "Unable to open the database file (SQLITE_CANTOPEN)" (#438 decision 4).
	if err = db.PingContext(ctx); err != nil {
		_ = db.Close()
		var sqliteErr *sqlitedriver.Error
		if errors.As(err, &sqliteErr) {
			return nil, errs.Wrapf(err, "unable to connect to database: %s", codeName(sqliteErr.Code()))
		}
		return nil, errs.Wrap(err, "unable to connect to database")
	}

	// Closed on a refused PRAGMA as on a refused ping, because the caller is handed no database to
	// close: a read-only file in DELETE journal mode connects, refuses WAL, and its pool used to
	// keep the file's descriptor for the life of the process (#438).
	if err = applyPragmas(ctx, db, dsn); err != nil {
		_ = db.Close()
		return nil, err
	}

	slog.InfoContext(ctx, "connected to sqlite database with required PRAGMA settings")
	commonDb := commondb.New(db, sqlbuilder.SQLite, logSQL)
	commonDb.IsDeadlock = isDeadlock
	commonDb.IsUniqueViolation = isUniqueViolation
	sqliteDb := Database{
		Database: commonDb,
	}

	return &sqliteDb, nil
}

// codeName is SQLite's name for a result code as the driver spells it, e.g. "Unable to open the
// database file (SQLITE_CANTOPEN)". The driver names every primary code but only some extended
// ones, so an extended code it leaves out, such as 1544 (SQLITE_READONLY_DIRECTORY) for a
// directory the server cannot write, is named by its primary code, the low byte, instead of
// printing as nothing.
func codeName(code int) string {
	if name, ok := sqlitedriver.ErrorCodeString[code]; ok {
		return name
	}
	return sqlitedriver.ErrorCodeString[code&0xff]
}

// applyPragmas sets the PRAGMAs Goiabada requires on db and reads each back, refusing a value
// that did not take. WAL is skipped for an in-memory database, which has no journal file.
func applyPragmas(ctx context.Context, db *sql.DB, dsn string) error {
	pragmaStatements := []string{
		"PRAGMA foreign_keys = ON;",
		"PRAGMA busy_timeout = 5000;",
	}

	// Only set journal_mode to WAL if it's not an in-memory database
	isMemoryDB := strings.Contains(dsn, ":memory:")
	if !isMemoryDB {
		pragmaStatements = append(pragmaStatements, "PRAGMA journal_mode = WAL;")
	}

	for _, stmt := range pragmaStatements {
		if _, err := db.ExecContext(ctx, stmt); err != nil {
			return errs.Wrapf(err, "failed to execute %s", stmt)
		}
	}

	// Verify PRAGMA settings
	pragmaChecks := []struct {
		name     string
		query    string
		expected any
	}{
		{"foreign_keys", "PRAGMA foreign_keys;", 1},
		{"busy_timeout", "PRAGMA busy_timeout;", 5000},
	}

	// Only check journal_mode if it's not an in-memory database
	if !isMemoryDB {
		pragmaChecks = append(pragmaChecks, struct {
			name     string
			query    string
			expected any
		}{"journal_mode", "PRAGMA journal_mode;", "wal"})
	}

	for _, check := range pragmaChecks {
		var value any
		if err := db.QueryRowContext(ctx, check.query).Scan(&value); err != nil {
			return errs.Wrapf(err, "unable to check %s status", check.name)
		}
		if fmt.Sprintf("%v", value) != fmt.Sprintf("%v", check.expected) {
			return errs.Errorf("%s is not set correctly. Expected %v, got %v", check.name, check.expected, value)
		}
	}
	return nil
}

// isDeadlock is SQLite's half of RunInTransaction's classifier, and it is always false: the
// pool has one connection (Pool above), so no two transactions of this process
// ever overlap and there is no cycle for the engine to break (#301).
func isDeadlock(error) bool {
	return false
}

// SQLite is the one engine that gives "a key already holds that value" three different extended
// result codes, depending on which kind of key was collided with. All three were observed rather
// than remembered, by running the statements against an in-memory database; the same statements
// are TestIsUniqueViolation's rows, so the numbers below are checked rather than trusted.
//
//	2067 SQLITE_CONSTRAINT_UNIQUE      a UNIQUE column constraint or a CREATE UNIQUE INDEX
//	1555 SQLITE_CONSTRAINT_PRIMARYKEY  a PRIMARY KEY, of any type, composite or WITHOUT ROWID
//	2579 SQLITE_CONSTRAINT_ROWID       an explicitly supplied rowid that is taken
//
// All three are accepted, because on the other three engines one number covers all of them:
// MySQL's 1062 says "Duplicate entry ... for key 'PRIMARY'", PostgreSQL's 23505 is unique_violation
// for a primary key too, and SQL Server's 2627 is "Violation of PRIMARY KEY constraint" as readily
// as of a UNIQUE one. Accepting only 2067 would make SQLite the single engine on which a primary-key
// collision is not a unique-key violation, which is the kind of divergence #279 exists to remove.
//
// The primary code these extend, SQLITE_CONSTRAINT (19), is deliberately absent: it also covers NOT
// NULL, CHECK and foreign-key refusals, none of which is a lost race for a key, and all of which a
// caller answering 409 would then tell the client to retry forever.
const (
	sqliteConstraintUnique     = 2067
	sqliteConstraintPrimaryKey = 1555
	sqliteConstraintRowid      = 2579
)

// isUniqueViolation is SQLite's row of the unique-key classifier table commondb's wrapSQLError consults.
//
// modernc.org/sqlite returns *sqlite.Error, with pointer receivers, so the pointer is the only form
// that is an error. errors.As rather than a type assertion, because by the time a caller asks, the
// error has been wrapped by whatever ran the statement.
func isUniqueViolation(err error) bool {
	var sqliteErr *sqlitedriver.Error
	if !errors.As(err, &sqliteErr) {
		return false
	}
	switch sqliteErr.Code() {
	case sqliteConstraintUnique, sqliteConstraintPrimaryKey, sqliteConstraintRowid:
		return true
	}
	return false
}

// schemaMigrationsTableDDL pins the shape of the version table the runner keeps, which
// Goiabada creates before anything migrates rather than leaving to whatever applies the
// files (#284 decision 7).
//
// SQLite is the one engine where this changed anything. golang-migrate v4.19.1's SQLite
// driver built `(version uint64, dirty bool)` here: both columns nullable, no primary key,
// and a separate version_unique index. Its MySQL, PostgreSQL and SQL Server drivers all
// built `version bigint not null primary key, dirty boolean not null`. A nullable version
// is not cosmetic: that shape accepts a NULL row Version() then cannot read back, and the
// four engines have to agree on this table's shape because the parity check reads it like
// any other. Migration 000041 does the same for a database created before this existed.
//
// INTEGER and not BIGINT. Only `INTEGER PRIMARY KEY` is a rowid alias; spelled BIGINT,
// SQLite builds sqlite_autoindex_schema_migrations_1 to enforce the key and
// schemaMigrationsIndexDDL below lands on top of it, leaving two unique indexes on one
// column where the other three engines have one.
const schemaMigrationsTableDDL = `CREATE TABLE IF NOT EXISTS schema_migrations (
	version INTEGER NOT NULL PRIMARY KEY,
	dirty BOOLEAN NOT NULL
)`

// schemaMigrationsIndexDDL is the statement golang-migrate's SQLite driver used to issue on
// every construction, and it is Goiabada's now that nothing else issues it (#268 decision 6).
//
// It has to survive the library leaving. Every SQLite database Goiabada has deployed carries
// this index and the golden file records it, so a fresh install without it would differ from
// a migrated one on a table the parity check reads like any other. Dropping it with a
// migration instead would move a golden and two tests for an index nobody queries by; this
// one statement leaves every one of them true.
//
// SQLite only. On the other three engines the version table has a real primary key, whose
// index is the only unique one on it.
const schemaMigrationsIndexDDL = `CREATE UNIQUE INDEX IF NOT EXISTS version_unique ON schema_migrations (version)`

// ensureSchemaMigrationsTable creates the version table at Goiabada's shape, and its index,
// when they are not there yet. Both statements are idempotent, so two processes starting
// against one empty database cannot make each other fail.
func (d *Database) ensureSchemaMigrationsTable(ctx context.Context) error {
	if _, err := d.DB.ExecContext(ctx, schemaMigrationsTableDDL); err != nil {
		return errs.Wrap(err, "unable to create the schema_migrations table")
	}
	if _, err := d.DB.ExecContext(ctx, schemaMigrationsIndexDDL); err != nil {
		return errs.Wrap(err, "unable to create the schema_migrations version index")
	}
	return nil
}

// NewMigrator builds a runner bound to this database and the embedded migration files.
// Startup brings it to head through UpToHead; tests use it to step to a specific version (e.g.
// seed at 000020, then apply 000021 in isolation).
//
// There is nothing to close. The runner takes a connection out of the pool for the duration
// of one operation and gives it back before returning (#268 decision 8).
//
// The Progress SQL Server's pre-create reports a lock wait to goes unused: the version table here is
// created by one idempotent statement, which waits for no migration lock.
func (d *Database) NewMigrator(ctx context.Context, _ migrator.Progress) (*migrator.Migrator, error) {
	if err := d.ensureSchemaMigrationsTable(ctx); err != nil {
		return nil, err
	}

	m, err := migrator.New(d.DB, sqliteMigrationsFs, "migrations", migrator.SQLite())
	if err != nil {
		return nil, errs.Wrap(err, "unable to create migration instance")
	}
	return m, nil
}
