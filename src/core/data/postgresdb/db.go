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
	"github.com/leodip/goiabada/core/config"
	"github.com/leodip/goiabada/core/data/commondb"
	"github.com/pkg/errors"
)

//go:embed migrations/*.sql
var postgresMigrationsFs embed.FS

type PostgresDatabase struct {
	DB       *sql.DB
	CommonDB *commondb.CommonDatabase
}

func NewPostgresDatabase() (*PostgresDatabase, error) {

	slog.Info("using database postgres")
	slog.Info(fmt.Sprintf("db username: %v", config.GetDatabase().Username))
	slog.Info(fmt.Sprintf("db host: %v", config.GetDatabase().Host))
	slog.Info(fmt.Sprintf("db port: %v", config.GetDatabase().Port))
	slog.Info(fmt.Sprintf("db name: %v", config.GetDatabase().Name))

	dbURL := fmt.Sprintf("postgres://%v:%v@%v:%v/%v",
		config.GetDatabase().Username,
		config.GetDatabase().Password,
		config.GetDatabase().Host,
		config.GetDatabase().Port,
		config.GetDatabase().Name)

	// Open with database/sql for commondb compatibility
	db, err := sql.Open("pgx", dbURL)
	if err != nil {
		return nil, errors.Wrap(err, "unable to open database")
	}

	// Create database if not exists
	defaultDB, err := sql.Open("pgx", fmt.Sprintf("postgres://%v:%v@%v:%v/postgres",
		config.GetDatabase().Username,
		config.GetDatabase().Password,
		config.GetDatabase().Host,
		config.GetDatabase().Port))
	if err != nil {
		return nil, errors.Wrap(err, "unable to connect to default database")
	}
	defer defaultDB.Close()

	_, err = defaultDB.Exec(fmt.Sprintf("CREATE DATABASE %v;", config.GetDatabase().Name))
	if err != nil && !strings.Contains(err.Error(), "already exists") {
		return nil, errors.Wrap(err, "unable to create database")
	}

	commonDb := commondb.NewCommonDatabase(db, sqlbuilder.PostgreSQL)

	postgresDb := PostgresDatabase{
		DB:       db,
		CommonDB: commonDb,
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
		DatabaseName: config.GetDatabase().Name,
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
