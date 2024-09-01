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
	"github.com/leodip/goiabada/core/config"
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

func NewSQLiteDatabase() (*SQLiteDatabase, error) {
	dsn := config.GetDatabase().DSN
	if dsn == "" {
		dsn = "file::memory:?cache=shared"
	}

	isMemoryDB := strings.Contains(dsn, ":memory:")
	slog.Info(fmt.Sprintf("using sqlite database: %v", dsn))

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
	commonDb := commondb.NewCommonDatabase(db, sqlbuilder.SQLite)
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

func (d *SQLiteDatabase) Migrate() error {
	driver, err := sqlite.WithInstance(d.DB, &sqlite.Config{})
	if err != nil {
		return errors.Wrap(err, "unable to create migration driver")
	}

	iofs, err := iofs.New(sqliteMigrationsFs, "migrations")
	if err != nil {
		return errors.Wrap(err, "unable to create migration filesystem")
	}

	migrate, err := gomigrate.NewWithInstance("iofs", iofs, "sqlite", driver)
	if err != nil {
		return errors.Wrap(err, "unable to create migration instance")
	}

	err = migrate.Up()
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

func (d *SQLiteDatabase) Seed() error {
	return d.CommonDB.Seed()
}
