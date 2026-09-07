package sqlitedb

import (
	"context"
	"database/sql"
	"embed"
	"fmt"
	"log/slog"
	"strings"

	"github.com/huandu/go-sqlbuilder"
	"github.com/leodip/goiabada/core/constants"
	"github.com/leodip/goiabada/core/data/commondb"
	"github.com/leodip/goiabada/core/data/migrator"
	"github.com/pkg/errors"
	sqlitedriver "modernc.org/sqlite"
)

//go:embed migrations/*.sql
var sqliteMigrationsFs embed.FS

type SQLiteDatabase struct {
	DB       *sql.DB
	CommonDB *commondb.CommonDatabase
}

type DatabaseConfig struct {
	Type     string
	Username string
	Password string
	Host     string
	Port     int
	Name     string
	DSN      string
}

// GOIABADA_DB_CREATE does not apply here, which is why DatabaseConfig has no Create field: there
// is no create statement and no maintenance connection on SQLite, and what decides whether an
// absent file is created is the operator's own DSN. The equivalent is mode=rw in it, which the
// driver honours by refusing to create the file (#293).
func NewSQLiteDatabase(dbConfig *DatabaseConfig, logSQL bool) (*SQLiteDatabase, error) {

	dsn := dbConfig.DSN
	if dsn == "" {
		dsn = "file::memory:?cache=shared"
	}

	slog.Info("using database sqlite")
	slog.Info(fmt.Sprintf("db dsn: %v", dbConfig.DSN))

	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, errors.Wrap(err, "unable to open database")
	}

	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	db.SetConnMaxLifetime(0)

	// Execute PRAGMA statements directly
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
		_, err = db.Exec(stmt)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to execute %s", stmt)
		}
	}

	// Verify PRAGMA settings
	pragmaChecks := []struct {
		name     string
		query    string
		expected interface{}
	}{
		{"foreign_keys", "PRAGMA foreign_keys;", 1},
		{"busy_timeout", "PRAGMA busy_timeout;", 5000},
	}

	// Only check journal_mode if it's not an in-memory database
	if !isMemoryDB {
		pragmaChecks = append(pragmaChecks, struct {
			name     string
			query    string
			expected interface{}
		}{"journal_mode", "PRAGMA journal_mode;", "wal"})
	}

	for _, check := range pragmaChecks {
		var value interface{}
		err = db.QueryRow(check.query).Scan(&value)
		if err != nil {
			return nil, errors.Wrapf(err, "unable to check %s status", check.name)
		}
		if fmt.Sprintf("%v", value) != fmt.Sprintf("%v", check.expected) {
			return nil, errors.Errorf("%s is not set correctly. Expected %v, got %v", check.name, check.expected, value)
		}
	}

	if err := db.PingContext(context.Background()); err != nil {
		if errWithCode, ok := err.(*sqlitedriver.Error); ok {
			err = errors.WithStack(errors.New(sqlitedriver.ErrorCodeString[errWithCode.Code()]))
		}
		return nil, errors.WithStack(fmt.Errorf("sqlite ping: %w", err))
	}

	slog.Info("connected to sqlite database with required PRAGMA settings")
	commonDb := commondb.NewCommonDatabase(db, sqlbuilder.SQLite, logSQL)
	commonDb.IsDeadlock = isDeadlock
	sqliteDb := SQLiteDatabase{
		DB:       db,
		CommonDB: commonDb,
	}

	return &sqliteDb, nil
}

func (d *SQLiteDatabase) BeginTransaction() (*sql.Tx, error) {
	return d.CommonDB.BeginTransaction()
}

func (d *SQLiteDatabase) RunInTransaction(fn func(tx *sql.Tx) error) error {
	return d.CommonDB.RunInTransaction(fn)
}

// isDeadlock is SQLite's half of RunInTransaction's classifier, and it is always false: the
// pool has one connection (SetMaxOpenConns(1) above), so no two transactions of this process
// ever overlap and there is no cycle for the engine to break (#301).
func isDeadlock(error) bool {
	return false
}

func (d *SQLiteDatabase) CommitTransaction(tx *sql.Tx) error {
	return d.CommonDB.CommitTransaction(tx)
}

func (d *SQLiteDatabase) RollbackTransaction(tx *sql.Tx) error {
	return d.CommonDB.RollbackTransaction(tx)
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
func (d *SQLiteDatabase) ensureSchemaMigrationsTable() error {
	if _, err := d.DB.Exec(schemaMigrationsTableDDL); err != nil {
		return errors.Wrap(err, "unable to create the schema_migrations table")
	}
	if _, err := d.DB.Exec(schemaMigrationsIndexDDL); err != nil {
		return errors.Wrap(err, "unable to create the schema_migrations version index")
	}
	return nil
}

// NewMigrator builds a runner bound to this database and the embedded migration files.
// Migrate delegates to it; tests use it to step to a specific version (e.g. seed at
// 000020, then apply 000021 in isolation).
//
// There is nothing to close. The runner takes a connection out of the pool for the duration
// of one operation and gives it back before returning (#268 decision 8).
func (d *SQLiteDatabase) NewMigrator() (*migrator.Migrator, error) {
	if err := d.ensureSchemaMigrationsTable(); err != nil {
		return nil, err
	}

	m, err := migrator.New(d.DB, sqliteMigrationsFs, "migrations", migrator.SQLite())
	if err != nil {
		return nil, errors.Wrap(err, "unable to create migration instance")
	}
	return m, nil
}

func (d *SQLiteDatabase) Migrate() error {
	m, err := d.NewMigrator()
	if err != nil {
		return err
	}

	err = m.Up()
	// IsNoChange rather than errors.Is: a run whose unlock failed answers the sentinel JOINED
	// with that failure, and errors.Is would report this start as successful while the migration
	// lock stays held against every other process on the database (#268).
	if migrator.IsNoChange(err) {
		slog.Info("no need to migrate the database")
		return nil
	}
	if err != nil {
		// StartupRefusal explains the one failure a starting server can be talked out of: a
		// database a newer release already migrated. Everything else passes through.
		return errors.Wrap(migrator.StartupRefusal(err, constants.Version), "unable to migrate the database")
	}

	return nil
}

func (d *SQLiteDatabase) IsEmpty() (bool, error) {
	return d.CommonDB.IsEmpty()
}
