package commondb

import (
	"database/sql"
	"fmt"
	"log/slog"

	"github.com/huandu/go-sqlbuilder"
	"github.com/pkg/errors"
	"github.com/spf13/viper"
)

type CommonDatabase struct {
	DB     *sql.DB
	Flavor sqlbuilder.Flavor
}

func NewCommonDatabase(db *sql.DB, flavor sqlbuilder.Flavor) *CommonDatabase {
	return &CommonDatabase{
		DB:     db,
		Flavor: flavor,
	}
}

func (d *CommonDatabase) BeginTransaction() (*sql.Tx, error) {
	if viper.GetBool("Log.Sql") {
		slog.Info("beginning transaction")
	}

	tx, err := d.DB.Begin()
	if err != nil {
		return nil, errors.Wrap(err, "unable to begin transaction")
	}
	return tx, nil
}

func (d *CommonDatabase) CommitTransaction(tx *sql.Tx) error {
	if viper.GetBool("Log.Sql") {
		slog.Info("committing transaction")
	}

	err := tx.Commit()
	if err != nil {
		return errors.Wrap(err, "unable to commit transaction")
	}
	return nil
}

func (d *CommonDatabase) RollbackTransaction(tx *sql.Tx) error {
	if viper.GetBool("Log.Sql") {
		slog.Info("rolling back transaction")
	}

	err := tx.Rollback()
	if err != nil {
		return errors.Wrap(err, "unable to rollback transaction")
	}
	return nil
}

func (d *CommonDatabase) Log(sql string, args ...any) {
	if viper.GetBool("Log.Sql") {
		slog.Info(fmt.Sprintf("sql: %v", sql))
		argsStr := ""
		for i, arg := range args {
			argsStr += fmt.Sprintf("[arg %v: %v] ", i, arg)
		}
		slog.Info(fmt.Sprintf("sql args: %v", argsStr))
	}
}

func (d *CommonDatabase) ExecSql(tx *sql.Tx, sql string, args ...any) (sql.Result, error) {

	d.Log(sql, args...)

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

func (d *CommonDatabase) QuerySql(tx *sql.Tx, sql string, args ...any) (*sql.Rows, error) {
	d.Log(sql, args...)

	if tx != nil {
		result, err := tx.Query(sql, args...)
		if err != nil {
			return nil, errors.Wrap(err, "unable to execute SQL")
		}
		return result, nil
	}

	rows, err := d.DB.Query(sql, args...)
	if err != nil {
		return nil, errors.Wrap(err, "unable to execute SQL")
	}
	return rows, nil
}
