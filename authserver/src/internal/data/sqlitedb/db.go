package sqlitedb

import (
	"context"
	"database/sql"
	"embed"
	"fmt"
	"log/slog"

	"github.com/golang-migrate/migrate/v4"
	"github.com/golang-migrate/migrate/v4/database/sqlite"
	"github.com/golang-migrate/migrate/v4/source/iofs"
	"github.com/huandu/go-sqlbuilder"
	"github.com/leodip/goiabada/internal/data/commondb"
	"github.com/pkg/errors"
	"github.com/spf13/viper"
	sqlitedriver "modernc.org/sqlite"
)

//go:embed migrations/*.sql
var sqliteMigrationsFs embed.FS

type SQLiteDatabase struct {
	DB       *sql.DB
	CommonDB *commondb.CommonDatabase
}

func NewSQLiteDatabase() (*SQLiteDatabase, error) {
	dsn := viper.GetString("DB.DSN")
	if dsn == "" {
		dsn = "file::memory:?cache=shared" // Default to in-memory database
	}

	slog.Info(fmt.Sprintf("using sqlite database: %v", dsn))

	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, errors.Wrap(err, "unable to open database")
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	db.SetConnMaxLifetime(0)

	if err := db.PingContext(context.Background()); err != nil {
		if errWithCode, ok := err.(*sqlitedriver.Error); ok {
			err = errors.WithStack(errors.New(sqlitedriver.ErrorCodeString[errWithCode.Code()]))
		}
		return nil, errors.WithStack(fmt.Errorf("sqlite ping: %w", err))
	}
	slog.Info("connected to sqlite database")

	commonDb := commondb.NewCommonDatabase(db, sqlbuilder.SQLite)

	mysqlDb := SQLiteDatabase{
		DB:       db,
		CommonDB: commonDb,
	}
	return &mysqlDb, nil
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

func (d *SQLiteDatabase) IsGoiabadaSchemaCreated() (bool, error) {
	var tableName string
	// check if the users table exists
	err := d.DB.QueryRow("SELECT name FROM sqlite_master WHERE type='table' AND name=?;", "users").Scan(&tableName)
	if err != nil {
		if err == sql.ErrNoRows {
			return false, nil // Table does not exist, no error
		}
		return false, errors.Wrap(err, "unable to query database")
	}
	return true, nil // Table exists
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

	migrate, err := migrate.NewWithInstance("iofs", iofs, "sqlite", driver)

	if err != nil {
		return errors.Wrap(err, "unable to create migration instance")
	}

	err = migrate.Up()
	if err != nil {
		return errors.Wrap(err, "unable to migrate database")
	}

	return nil
}
