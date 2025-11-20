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
	"github.com/leodip/goiabada/core/data/commondb"
	_ "github.com/microsoft/go-mssqldb"
	"github.com/pkg/errors"
)

//go:embed migrations/*.sql
var mssqlMigrationsFs embed.FS

type MsSQLDatabase struct {
	DB       *sql.DB
	CommonDB *commondb.CommonDatabase
	dbConfig *DatabaseConfig
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

func NewMsSQLDatabase(dbConfig *DatabaseConfig, logSQL bool) (*MsSQLDatabase, error) {

	slog.Info("using database mssql")
	slog.Info(fmt.Sprintf("db username: %v", dbConfig.Username))
	slog.Info(fmt.Sprintf("db host: %v", dbConfig.Host))
	slog.Info(fmt.Sprintf("db port: %v", dbConfig.Port))
	slog.Info(fmt.Sprintf("db name: %v", dbConfig.Name))

	// SQL Server connection string format
	queryParams := url.Values{}
	queryParams.Add("database", "master") // Connect to master first to create DB
	queryParams.Add("encrypt", "disable") // Disable encryption requirement

	connStringMaster := url.URL{
		Scheme:   "sqlserver",
		User:     url.UserPassword(dbConfig.Username, dbConfig.Password),
		Host:     fmt.Sprintf("%s:%d", dbConfig.Host, dbConfig.Port),
		RawQuery: queryParams.Encode(),
	}

	// Connect to master database first
	masterDB, err := sql.Open("sqlserver", connStringMaster.String())
	if err != nil {
		return nil, errors.Wrap(err, "unable to open master database")
	}
	defer func() { _ = masterDB.Close() }() // Ensure we close the master connection

	// Test the connection
	err = masterDB.Ping()
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
		dbConfig.Name,
		dbConfig.Name,
	)

	_, err = masterDB.Exec(createDatabaseCommand)
	if err != nil {
		return nil, errors.Wrap(err, "unable to create database")
	}

	// Now connect to the actual database
	queryParams.Set("database", dbConfig.Name)
	connString := url.URL{
		Scheme:   "sqlserver",
		User:     url.UserPassword(dbConfig.Username, dbConfig.Password),
		Host:     fmt.Sprintf("%s:%d", dbConfig.Host, dbConfig.Port),
		RawQuery: queryParams.Encode(),
	}

	// Connect to the actual database
	db, err := sql.Open("sqlserver", connString.String())
	if err != nil {
		return nil, errors.Wrap(err, "unable to open database")
	}

	// Test the connection to the new database
	err = db.Ping()
	if err != nil {
		_ = db.Close()
		return nil, errors.Wrap(err, "unable to connect to created database")
	}

	commonDb := commondb.NewCommonDatabase(db, sqlbuilder.SQLServer, logSQL)

	mssqlDb := MsSQLDatabase{
		DB:       db,
		CommonDB: commonDb,
		dbConfig: dbConfig,
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
		DatabaseName: d.dbConfig.Name,
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
