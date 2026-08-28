package sqlitedb

import (
	"context"
	"database/sql"
	"embed"
	"fmt"
	"log/slog"
	"strings"

	gomigrate "github.com/golang-migrate/migrate/v4"
	"github.com/golang-migrate/migrate/v4/database/sqlite"
	"github.com/golang-migrate/migrate/v4/source/iofs"
	"github.com/huandu/go-sqlbuilder"
	"github.com/leodip/goiabada/core/data/commondb"
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
	sqliteDb := SQLiteDatabase{
		DB:       db,
		CommonDB: commonDb,
	}

	return &sqliteDb, nil
}

func (d *SQLiteDatabase) BeginTransaction() (*sql.Tx, error) {
	return d.CommonDB.BeginTransaction()
}

func (d *SQLiteDatabase) CommitTransaction(tx *sql.Tx) error {
	return d.CommonDB.CommitTransaction(tx)
}

func (d *SQLiteDatabase) RollbackTransaction(tx *sql.Tx) error {
	return d.CommonDB.RollbackTransaction(tx)
}

// NewMigrator builds a golang-migrate instance bound to this database and the
// embedded migration files. Migrate delegates to it; tests use it to step to a
// specific version (e.g. seed at 000020, then apply 000021 in isolation).
// schemaMigrationsTableDDL pins the shape of golang-migrate's own version table, which
// Goiabada creates before handing the database over rather than leaving to the driver
// (#284 decision 7).
//
// SQLite is the one engine whose driver is out of line. golang-migrate v4.19.1 builds
// `(version uint64, dirty bool)` here: both columns nullable, no primary key, and a
// separate version_unique index. The MySQL, PostgreSQL and SQL Server drivers all build
// `version bigint not null primary key, dirty boolean not null`. A nullable version is not
// cosmetic: the driver's own shape accepts a NULL row that Version() then cannot read back,
// and the four engines have to agree on this table's shape because the parity check reads
// it like any other.
//
// Every driver creates the table only if it is absent, so issuing this first makes the
// driver's statement a no-op and the shape Goiabada's on a new install; a dependency bump
// that changed the driver's DDL cannot silently change what Goiabada builds. Migration
// 000041 does the same for a database created before this existed.
//
// INTEGER and not BIGINT. Only `INTEGER PRIMARY KEY` is a rowid alias; spelled BIGINT,
// SQLite builds sqlite_autoindex_schema_migrations_1 to enforce the key and the driver's
// unconditional `CREATE UNIQUE INDEX IF NOT EXISTS version_unique` lands on top of it,
// leaving two unique indexes on one column where the other three engines have one.
const schemaMigrationsTableDDL = `CREATE TABLE IF NOT EXISTS schema_migrations (
	version INTEGER NOT NULL PRIMARY KEY,
	dirty BOOLEAN NOT NULL
)`

// ensureSchemaMigrationsTable creates the version table at Goiabada's shape when it is not
// there yet. The driver's own ensureVersionTable then runs on every migrator construction
// and, on this engine, adds only its version_unique index on top.
func (d *SQLiteDatabase) ensureSchemaMigrationsTable() error {
	if _, err := d.DB.Exec(schemaMigrationsTableDDL); err != nil {
		return errors.Wrap(err, "unable to create the schema_migrations table")
	}
	return nil
}

func (d *SQLiteDatabase) NewMigrator() (*gomigrate.Migrate, error) {
	if err := d.ensureSchemaMigrationsTable(); err != nil {
		return nil, err
	}

	driver, err := sqlite.WithInstance(d.DB, &sqlite.Config{})
	if err != nil {
		return nil, errors.Wrap(err, "unable to create migration driver")
	}

	iofs, err := iofs.New(sqliteMigrationsFs, "migrations")
	if err != nil {
		return nil, errors.Wrap(err, "unable to create migration filesystem")
	}

	migrator, err := gomigrate.NewWithInstance("iofs", iofs, "sqlite", driver)
	if err != nil {
		return nil, errors.Wrap(err, "unable to create migration instance")
	}
	return migrator, nil
}

func (d *SQLiteDatabase) Migrate() error {
	migrator, err := d.NewMigrator()
	if err != nil {
		return err
	}

	err = migrator.Up()
	if err != nil && err != gomigrate.ErrNoChange {
		return errors.Wrap(err, "unable to migrate the database")
	} else if err != nil && err == gomigrate.ErrNoChange {
		slog.Info("no need to migrate the database")
	}

	return nil
}

func (d *SQLiteDatabase) IsEmpty() (bool, error) {
	return d.CommonDB.IsEmpty()
}
