package commondb

import (
	"context"
	"database/sql"

	"github.com/leodip/goiabada/core/errs"
)

// queryOne runs a read of one record and scans its first row, answering nil when there is none.
// noun reaches the scan failure's message, "unable to scan <noun>".
//
// rows.Err() is checked when no row came back, because a driver may report a failed query through
// the result set rather than from the call, and every getter here reports a missing row as
// (nil, nil): without the check a failed read would read as an absence. See QuerySQL.
func queryOne[T any](ctx context.Context, d *Database, tx *sql.Tx, query string, args []any,
	scan func(rowScanner, *T) error, noun string) (*T, error) {

	rows, err := d.QuerySQL(ctx, tx, query, args...)
	if err != nil {
		return nil, errs.Wrap(err, "unable to query database")
	}
	defer func() { _ = rows.Close() }()

	if rows.Next() {
		var record T
		if err := scan(rows, &record); err != nil {
			return nil, errs.Wrap(err, "unable to scan "+noun)
		}
		return &record, nil
	}
	if err := rows.Err(); err != nil {
		return nil, errs.Wrap(err, "unable to read query results")
	}

	return nil, nil
}

// queryAll runs a read of any number of records and scans every row, appending to into, which is
// how a read issued once per batch of ids gathers its batches. It answers into unchanged, nil
// included, when no row comes back.
func queryAll[T any](ctx context.Context, d *Database, tx *sql.Tx, into []T, query string, args []any,
	scan func(rowScanner, *T) error, noun string) ([]T, error) {

	rows, err := d.QuerySQL(ctx, tx, query, args...)
	if err != nil {
		return nil, errs.Wrap(err, "unable to query database")
	}
	defer func() { _ = rows.Close() }()

	for rows.Next() {
		var record T
		if err := scan(rows, &record); err != nil {
			return nil, errs.Wrap(err, "unable to scan "+noun)
		}
		into = append(into, record)
	}

	if err := rows.Err(); err != nil {
		return nil, errs.Wrap(err, "unable to read query results")
	}

	return into, nil
}
