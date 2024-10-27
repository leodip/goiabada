package mysqldb

import (
	"database/sql"
	"embed"
	"fmt"
	"log/slog"
	"strings"

	_ "github.com/go-sql-driver/mysql"
	gomigrate "github.com/golang-migrate/migrate/v4"
	"github.com/golang-migrate/migrate/v4/database/mysql"
	"github.com/golang-migrate/migrate/v4/source/iofs"
	"github.com/huandu/go-sqlbuilder"
	"github.com/leodip/goiabada/core/config"
	"github.com/leodip/goiabada/core/data/commondb"
	"github.com/pkg/errors"
)

//go:embed migrations/*.sql
var mysqlMigrationsFs embed.FS

type MySQLDatabase struct {
	DB       *sql.DB
	CommonDB *commondb.CommonDatabase
}

func NewMySQLDatabase() (*MySQLDatabase, error) {
	dsnWithoutDBname := fmt.Sprintf("%v:%v@tcp(%v:%v)/?charset=utf8mb4&parseTime=True&loc=UTC",
		config.GetDatabase().Username,
		config.GetDatabase().Password,
		config.GetDatabase().Host,
		config.GetDatabase().Port)

	dsnWithDBname := fmt.Sprintf("%v:%v@tcp(%v:%v)/%v?charset=utf8mb4&parseTime=True&loc=UTC&multiStatements=true",
		config.GetDatabase().Username,
		config.GetDatabase().Password,
		config.GetDatabase().Host,
		config.GetDatabase().Port,
		config.GetDatabase().Name)

	var logMsg string
	if strings.TrimSpace(config.GetDatabase().Password) != "" {
		logMsg = strings.ReplaceAll(dsnWithDBname, config.GetDatabase().Password, "******")
	} else {
		logMsg = dsnWithDBname
	}
	slog.Info(fmt.Sprintf("using database: %v", logMsg))

	db, err := sql.Open("mysql", dsnWithoutDBname)
	if err != nil {
		return nil, errors.Wrap(err, "unable to open database")
	}

	// create the database if it does not exist
	createDatabaseCommand := fmt.Sprintf("CREATE DATABASE IF NOT EXISTS %v CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci;", config.GetDatabase().Name)
	_, err = db.Exec(createDatabaseCommand)
	if err != nil {
		return nil, errors.Wrap(err, "unable to create database")
	}

	db, err = sql.Open("mysql", dsnWithDBname)
	if err != nil {
		return nil, errors.Wrap(err, "unable to open database")
	}

	commonDb := commondb.NewCommonDatabase(db, sqlbuilder.MySQL)

	mysqlDb := MySQLDatabase{
		DB:       db,
		CommonDB: commonDb,
	}
	return &mysqlDb, nil
}

func (d *MySQLDatabase) BeginTransaction() (*sql.Tx, error) {
	return d.CommonDB.BeginTransaction()
}

func (d *MySQLDatabase) CommitTransaction(tx *sql.Tx) error {
	return d.CommonDB.CommitTransaction(tx)
}

func (d *MySQLDatabase) RollbackTransaction(tx *sql.Tx) error {
	return d.CommonDB.RollbackTransaction(tx)
}

func (d *MySQLDatabase) Migrate() error {
	driver, err := mysql.WithInstance(d.DB, &mysql.Config{
		DatabaseName: config.GetDatabase().Name,
	})
	if err != nil {
		return errors.Wrap(err, "unable to create migration driver")
	}

	iofs, err := iofs.New(mysqlMigrationsFs, "migrations")
	if err != nil {
		return errors.Wrap(err, "unable to create migration filesystem")
	}

	migrate, err := gomigrate.NewWithInstance("iofs", iofs, "mysql", driver)
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

func (d *MySQLDatabase) IsEmpty() (bool, error) {
	return d.CommonDB.IsEmpty()
}

func (d *MySQLDatabase) Seed() error {
	return d.CommonDB.Seed()
}
