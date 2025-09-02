package postgresdb

import (
	"database/sql"
	"embed"
	"fmt"
	"log/slog"
	"strings"

	gomigrate "github.com/golang-migrate/migrate/v4"
	"github.com/golang-migrate/migrate/v4/database/postgres"
	"github.com/golang-migrate/migrate/v4/source/iofs"
	"github.com/huandu/go-sqlbuilder"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/leodip/goiabada/core/data/commondb"
	"github.com/pkg/errors"
)

//go:embed migrations/*.sql
var postgresMigrationsFs embed.FS

type PostgresDatabase struct {
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

func NewPostgresDatabase(dbConfig *DatabaseConfig, logSQL bool) (*PostgresDatabase, error) {

	slog.Info("using database postgres")
	slog.Info(fmt.Sprintf("db username: %v", dbConfig.Username))
	slog.Info(fmt.Sprintf("db host: %v", dbConfig.Host))
	slog.Info(fmt.Sprintf("db port: %v", dbConfig.Port))
	slog.Info(fmt.Sprintf("db name: %v", dbConfig.Name))

	dbURL := fmt.Sprintf("postgres://%v:%v@%v:%v/%v",
		dbConfig.Username,
		dbConfig.Password,
		dbConfig.Host,
		dbConfig.Port,
		dbConfig.Name)

	// Open with database/sql for commondb compatibility
	db, err := sql.Open("pgx", dbURL)
	if err != nil {
		return nil, errors.Wrap(err, "unable to open database")
	}

	// Create database if not exists
	defaultDB, err := sql.Open("pgx", fmt.Sprintf("postgres://%v:%v@%v:%v/postgres",
		dbConfig.Username,
		dbConfig.Password,
		dbConfig.Host,
		dbConfig.Port))
	if err != nil {
		return nil, errors.Wrap(err, "unable to connect to default database")
	}
	defer defaultDB.Close()

	_, err = defaultDB.Exec(fmt.Sprintf("CREATE DATABASE %v;", dbConfig.Name))
	if err != nil && !strings.Contains(err.Error(), "already exists") {
		return nil, errors.Wrap(err, "unable to create database")
	}

	commonDb := commondb.NewCommonDatabase(db, sqlbuilder.PostgreSQL, logSQL)

	postgresDb := PostgresDatabase{
		DB:       db,
		CommonDB: commonDb,
		dbConfig: dbConfig,
	}
	return &postgresDb, nil
}

func (d *PostgresDatabase) BeginTransaction() (*sql.Tx, error) {
	return d.CommonDB.BeginTransaction()
}

func (d *PostgresDatabase) CommitTransaction(tx *sql.Tx) error {
	return d.CommonDB.CommitTransaction(tx)
}

func (d *PostgresDatabase) RollbackTransaction(tx *sql.Tx) error {
	return d.CommonDB.RollbackTransaction(tx)
}

func (d *PostgresDatabase) Migrate() error {
	driver, err := postgres.WithInstance(d.DB, &postgres.Config{
		DatabaseName: d.dbConfig.Name,
	})
	if err != nil {
		return errors.Wrap(err, "unable to create migration driver")
	}

	iofs, err := iofs.New(postgresMigrationsFs, "migrations")
	if err != nil {
		return errors.Wrap(err, "unable to create migration filesystem")
	}

	migrate, err := gomigrate.NewWithInstance("iofs", iofs, "postgres", driver)
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

func (d *PostgresDatabase) IsEmpty() (bool, error) {
	return d.CommonDB.IsEmpty()
}
