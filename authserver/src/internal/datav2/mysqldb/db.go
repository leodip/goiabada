package mysqldb

import (
	"database/sql"
	"embed"
	"fmt"
	"log/slog"
	"strings"

	_ "github.com/go-sql-driver/mysql"
	"github.com/golang-migrate/migrate/v4"
	"github.com/golang-migrate/migrate/v4/database/mysql"
	"github.com/golang-migrate/migrate/v4/source/iofs"
	"github.com/pkg/errors"
	"github.com/spf13/viper"
)

//go:embed migrations/*.sql
var mysqlMigrationsFs embed.FS

type MySQLDatabase struct {
	DB *sql.DB
}

func NewMySQLDatabase() (*MySQLDatabase, error) {
	dsnWithoutDBname := fmt.Sprintf("%v:%v@tcp(%v:%v)/?charset=utf8mb4&parseTime=True&loc=UTC",
		viper.GetString("DB.Username"),
		viper.GetString("DB.Password"),
		viper.GetString("DB.Host"),
		viper.GetInt("DB.Port"))

	dsnWithDBname := fmt.Sprintf("%v:%v@tcp(%v:%v)/%v?charset=utf8mb4&parseTime=True&loc=UTC&multiStatements=true",
		viper.GetString("DB.Username"),
		viper.GetString("DB.Password"),
		viper.GetString("DB.Host"),
		viper.GetInt("DB.Port"),
		viper.GetString("DB.DbName"))

	logMsg := strings.ReplaceAll(dsnWithDBname, viper.GetString("DB.Password"), "******")
	slog.Info(fmt.Sprintf("using database: %v", logMsg))

	db, err := sql.Open("mysql", dsnWithoutDBname)
	if err != nil {
		return nil, errors.Wrap(err, "unable to open database")
	}

	// create the database if it does not exist
	createDatabaseCommand := fmt.Sprintf("CREATE DATABASE IF NOT EXISTS %v CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci;", viper.GetString("DB.DbName"))
	_, err = db.Exec(createDatabaseCommand)
	if err != nil {
		return nil, errors.Wrap(err, "unable to create database")
	}

	db, err = sql.Open("mysql", dsnWithDBname)
	if err != nil {
		return nil, errors.Wrap(err, "unable to open database")
	}

	mysqlDb := MySQLDatabase{DB: db}
	return &mysqlDb, nil
}

func (d *MySQLDatabase) BeginTransaction() (*sql.Tx, error) {
	if viper.GetBool("Log.Sql") {
		slog.Info("beginning transaction")
	}

	tx, err := d.DB.Begin()
	if err != nil {
		return nil, errors.Wrap(err, "unable to begin transaction")
	}
	return tx, nil
}

func (d *MySQLDatabase) CommitTransaction(tx *sql.Tx) error {
	if viper.GetBool("Log.Sql") {
		slog.Info("committing transaction")
	}

	err := tx.Commit()
	if err != nil {
		return errors.Wrap(err, "unable to commit transaction")
	}
	return nil
}

func (d *MySQLDatabase) RollbackTransaction(tx *sql.Tx) error {
	if viper.GetBool("Log.Sql") {
		slog.Info("rolling back transaction")
	}

	err := tx.Rollback()
	if err != nil {
		return errors.Wrap(err, "unable to rollback transaction")
	}
	return nil
}

func (d *MySQLDatabase) IsGoiabadaSchemaCreated() (bool, error) {
	var count int
	// check if the users table exists
	err := d.DB.QueryRow("SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = ? AND table_name = ?", viper.GetString("DB.DbName"), "users").Scan(&count)
	if err != nil {
		return false, errors.Wrap(err, "unable to query database")
	}
	return count > 0, nil
}

func (d *MySQLDatabase) Migrate() error {
	driver, err := mysql.WithInstance(d.DB, &mysql.Config{
		DatabaseName: viper.GetString("DB.DbName"),
	})
	if err != nil {
		return errors.Wrap(err, "unable to create migration driver")
	}

	iofs, err := iofs.New(mysqlMigrationsFs, "migrations")
	if err != nil {
		return errors.Wrap(err, "unable to create migration filesystem")
	}

	migrate, err := migrate.NewWithInstance("iofs", iofs, "mysql", driver)

	if err != nil {
		return errors.Wrap(err, "unable to create migration instance")
	}
	migrate.Up()

	return nil
}
func (d *MySQLDatabase) log(sql string, args ...any) {
	if viper.GetBool("Log.Sql") {
		slog.Info(fmt.Sprintf("sql: %v", sql))
		argsStr := ""
		for i, arg := range args {
			argsStr += fmt.Sprintf("[arg %v: %v] ", i, arg)
		}
		slog.Info(fmt.Sprintf("sql args: %v", argsStr))
	}
}

func (d *MySQLDatabase) execSql(tx *sql.Tx, sql string, args ...any) (sql.Result, error) {

	d.log(sql, args...)

	if tx != nil {
		result, err := tx.Exec(sql, args...)
		if err != nil {
			return nil, errors.Wrap(err, "unable to execute SQL")
		}
		return result, nil
	}

	result, err := d.DB.Exec(sql, args...)
	if err != nil {
		return nil, errors.Wrap(err, "unable to execute SQL")
	}
	return result, nil
}

func (d *MySQLDatabase) querySql(tx *sql.Tx, sql string, args ...any) (*sql.Rows, error) {
	d.log(sql, args...)

	if tx != nil {
		result, err := tx.Query(sql, args...)
		if err != nil {
			return nil, errors.Wrap(err, "unable to execute SQL")
		}
		return result, nil
	}

	result, err := d.DB.Query(sql, args...)
	if err != nil {
		return nil, errors.Wrap(err, "unable to execute SQL")
	}
	return result, nil
}
