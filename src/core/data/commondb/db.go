package commondb

import (
	"database/sql"
	"fmt"
	"log/slog"

	"github.com/huandu/go-sqlbuilder"
	"github.com/pkg/errors"
)

type CommonDatabase struct {
	DB     *sql.DB
	Flavor sqlbuilder.Flavor
	logSQL bool
}

func NewCommonDatabase(db *sql.DB, flavor sqlbuilder.Flavor, logSQL bool) *CommonDatabase {
	return &CommonDatabase{
		DB:     db,
		Flavor: flavor,
		logSQL: logSQL,
	}
}

func (d *CommonDatabase) BeginTransaction() (*sql.Tx, error) {
	if d.logSQL {
		slog.Info("beginning transaction")
	}

	tx, err := d.DB.Begin()
	if err != nil {
		return nil, errors.Wrap(err, "unable to begin transaction")
	}
	return tx, nil
}

func (d *CommonDatabase) CommitTransaction(tx *sql.Tx) error {
	if d.logSQL {
		slog.Info("committing transaction")
	}

	err := tx.Commit()
	if err != nil {
		return errors.Wrap(err, "unable to commit transaction")
	}
	return nil
}

func (d *CommonDatabase) RollbackTransaction(tx *sql.Tx) error {
	if d.logSQL {
		slog.Info("rolling back transaction")
	}

	err := tx.Rollback()
	if err != nil {
		return errors.Wrap(err, "unable to rollback transaction")
	}
	return nil
}

// inTransaction runs fn inside a transaction: the caller's when one was supplied,
// otherwise one of its own that it commits or rolls back. It lets a method that
// needs several statements be atomic without forcing every caller to open a
// transaction, and without silently splitting the work when they didn't.
func (d *CommonDatabase) inTransaction(tx *sql.Tx, fn func(tx *sql.Tx) error) error {
	if tx != nil {
		return fn(tx)
	}

	ownTx, err := d.BeginTransaction()
	if err != nil {
		return err
	}

	if err := fn(ownTx); err != nil {
		_ = d.RollbackTransaction(ownTx)
		return err
	}

	return d.CommitTransaction(ownTx)
}

func (d *CommonDatabase) Log(sql string, args ...any) {
	if d.logSQL {
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

// QuerySql runs a query and returns its rows.
//
// Callers must check rows.Err() once iteration stops, not only the error returned
// here. A driver is free to report a failure through the result set rather than
// from the query call, and in that case Next() simply returns false. Reading a
// single row then means the caller cannot distinguish "no such row" from "the
// query failed", and every getter here reports a missing row as (nil, nil), so
// without the check a failed read is indistinguishable from a legitimate absence.
// For the getters behind permission and session lookups, that is the wrong
// direction to fail in.
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

func (d *CommonDatabase) IsEmpty() (bool, error) {
	settings, err := d.GetSettingsById(nil, 1)
	if err != nil {
		return false, errors.Wrap(err, "failed to check if database is empty")
	}

	return settings == nil, nil
}
