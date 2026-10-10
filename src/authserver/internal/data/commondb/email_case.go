package commondb

import (
	"context"
	"database/sql"

	"github.com/huandu/go-sqlbuilder"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/errs"
)

// ScanEmailCase reads every users row as its id, its stored address, and that address as THIS
// engine's own LOWER() reduces it. It is the whole of the read behind the startup pre-flight
// (datafactory.CheckEmailCaseBeforeMigrating) and does no comparing of its own, because the
// comparison is a Go rule and the engines disagree about the SQL one (#351).
//
// LOWER(email) is selected rather than computed, and that is the point of the method. Migration
// 000047 repairs exactly the rows its own `WHERE email <> LOWER(email)` selects, so the only way
// to know what it will miss is to ask the engine what it thinks LOWER(email) is and compare that
// against strings.ToLower. A predicate written here would be answering with the engine that is
// running rather than about it.
//
// The whole table, unfiltered: the caller needs both hazards off one read. A filter would leave
// the collision check unable to see the lowercase twin of a mixed-case address, which is the row
// that makes it a collision. It runs once per upgrade, before the migration chain, and never
// again afterwards.
func (d *Database) ScanEmailCase(ctx context.Context) ([]record.EmailCaseRow, error) {
	return d.scanEmailCase(func(query string, args []any) (*sql.Rows, error) {
		return d.QuerySQL(ctx, nil, query, args...)
	})
}

// ScanEmailCaseOn is ScanEmailCase read on conn: the migration runner's own connection, which holds
// the migration lock while a starting server runs the pre-flight under it (#542 decision 2). On
// SQLite that connection is the pool's only one, so the read must go through it rather than the
// pool, which would wait for it for ever.
func (d *Database) ScanEmailCaseOn(ctx context.Context, conn *sql.Conn) ([]record.EmailCaseRow, error) {
	return d.scanEmailCase(func(query string, args []any) (*sql.Rows, error) {
		d.log(ctx, query)
		rows, err := conn.QueryContext(ctx, query, args...)
		if err != nil {
			return nil, d.wrapSQLError(err, "unable to execute SQL")
		}
		return rows, nil
	})
}

// scanEmailCase is the read both run, through query.
func (d *Database) scanEmailCase(query func(query string, args []any) (*sql.Rows, error)) ([]record.EmailCaseRow, error) {
	sb := sqlbuilder.NewSelectBuilder()
	sb.Select("id", "email", "LOWER(email)").From("users")
	statement, args := sb.BuildWithFlavor(d.Flavor)

	rows, err := query(statement, args)
	if err != nil {
		return nil, errs.Wrap(err, "unable to query users for the email case pre-flight")
	}
	defer func() { _ = rows.Close() }()

	var result []record.EmailCaseRow
	for rows.Next() {
		var row record.EmailCaseRow
		if err := rows.Scan(&row.Id, &row.Email, &row.EngineLowered); err != nil {
			return nil, errs.Wrap(err, "unable to scan a user email for the email case pre-flight")
		}
		result = append(result, row)
	}
	if err := rows.Err(); err != nil {
		return nil, errs.Wrap(err, "error iterating users for the email case pre-flight")
	}

	return result, nil
}
