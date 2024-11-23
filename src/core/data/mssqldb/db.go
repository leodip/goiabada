package mssqldb

import (
	"database/sql"
	"embed"
	"fmt"
	"log/slog"
	"net/url"

	gomigrate "github.com/golang-migrate/migrate/v4"
	"github.com/golang-migrate/migrate/v4/database/sqlserver"
	"github.com/golang-migrate/migrate/v4/source/iofs"
	"github.com/huandu/go-sqlbuilder"
	"github.com/leodip/goiabada/core/config"
	"github.com/leodip/goiabada/core/data/commondb"
	_ "github.com/microsoft/go-mssqldb"
	"github.com/pkg/errors"
)

//go:embed migrations/*.sql
var mssqlMigrationsFs embed.FS

type MsSQLDatabase struct {
	DB       *sql.DB
	CommonDB *commondb.CommonDatabase
}

func NewMsSQLDatabase() (*MsSQLDatabase, error) {

	slog.Info("using database mssql")
	slog.Info(fmt.Sprintf("db username: %v", config.GetDatabase().Username))
	slog.Info(fmt.Sprintf("db host: %v", config.GetDatabase().Host))
	slog.Info(fmt.Sprintf("db port: %v", config.GetDatabase().Port))
	slog.Info(fmt.Sprintf("db name: %v", config.GetDatabase().Name))

	// SQL Server connection string format
	queryParams := url.Values{}
	queryParams.Add("database", "master") // Connect to master first to create DB
	queryParams.Add("encrypt", "disable") // Disable encryption requirement

	connStringMaster := url.URL{
		Scheme:   "sqlserver",
		User:     url.UserPassword(config.GetDatabase().Username, config.GetDatabase().Password),
		Host:     fmt.Sprintf("%s:%d", config.GetDatabase().Host, config.GetDatabase().Port),
		RawQuery: queryParams.Encode(),
	}

	// Connect to master database first
	db, err := sql.Open("sqlserver", connStringMaster.String())
	if err != nil {
		return nil, errors.Wrap(err, "unable to open master database")
	}
	defer db.Close() // Ensure we close the master connection

	// Test the connection
	err = db.Ping()
	if err != nil {
		return nil, errors.Wrap(err, "unable to connect to master database")
	}

	// Create database if it doesn't exist
	createDatabaseCommand := fmt.Sprintf(`
        IF NOT EXISTS (SELECT * FROM sys.databases WHERE name = N'%s')
        BEGIN
            CREATE DATABASE [%s]
            COLLATE Latin1_General_100_CI_AI_SC_UTF8
        END`,
		config.GetDatabase().Name,
		config.GetDatabase().Name,
	)

	_, err = db.Exec(createDatabaseCommand)
	if err != nil {
		return nil, errors.Wrap(err, "unable to create database")
	}

	// Now connect to the actual database
	queryParams.Set("database", config.GetDatabase().Name)
	connString := url.URL{
		Scheme:   "sqlserver",
		User:     url.UserPassword(config.GetDatabase().Username, config.GetDatabase().Password),
		Host:     fmt.Sprintf("%s:%d", config.GetDatabase().Host, config.GetDatabase().Port),
		RawQuery: queryParams.Encode(),
	}

	// Connect to the actual database
	db, err = sql.Open("sqlserver", connString.String())
	if err != nil {
		return nil, errors.Wrap(err, "unable to open database")
	}

	// Test the connection to the new database
	err = db.Ping()
	if err != nil {
		db.Close()
		return nil, errors.Wrap(err, "unable to connect to created database")
	}

	commonDb := commondb.NewCommonDatabase(db, sqlbuilder.SQLServer)

	mssqlDb := MsSQLDatabase{
		DB:       db,
		CommonDB: commonDb,
	}
	return &mssqlDb, nil
}

func (d *MsSQLDatabase) BeginTransaction() (*sql.Tx, error) {
	return d.CommonDB.BeginTransaction()
}

func (d *MsSQLDatabase) CommitTransaction(tx *sql.Tx) error {
	return d.CommonDB.CommitTransaction(tx)
}

func (d *MsSQLDatabase) RollbackTransaction(tx *sql.Tx) error {
	return d.CommonDB.RollbackTransaction(tx)
}

func (d *MsSQLDatabase) Migrate() error {
	driver, err := sqlserver.WithInstance(d.DB, &sqlserver.Config{
		DatabaseName: config.GetDatabase().Name,
	})
	if err != nil {
		return errors.Wrap(err, "unable to create migration driver")
	}

	iofs, err := iofs.New(mssqlMigrationsFs, "migrations")
	if err != nil {
		return errors.Wrap(err, "unable to create migration filesystem")
	}

	migrate, err := gomigrate.NewWithInstance("iofs", iofs, "sqlserver", driver)
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

func (d *MsSQLDatabase) IsEmpty() (bool, error) {
	return d.CommonDB.IsEmpty()
}
