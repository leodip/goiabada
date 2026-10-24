package commondb

import (
	"context"
	"database/sql"
	"time"

	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/errs"
)

// webOriginColumns is the web_origins table as scanWebOrigin reads it.
var webOriginColumns = columnList{
	sqlite:   "id, created_at, origin, client_id",
	mysql:    "id, created_at, origin, client_id",
	postgres: "id, created_at, origin, client_id",
	mssql:    "id, created_at, origin, client_id",
}

// scanWebOrigin reads one row selected with webOriginColumns.
func scanWebOrigin(row rowScanner, webOrigin *record.WebOrigin) error {
	return row.Scan(
		&webOrigin.Id,
		&webOrigin.CreatedAt,
		&webOrigin.Origin,
		&webOrigin.ClientId,
	)
}

var insertWebOrigin = statement{
	sqlite:   "INSERT INTO web_origins (created_at, origin, client_id) VALUES (?, ?, ?)",
	mysql:    "INSERT INTO web_origins (created_at, origin, client_id) VALUES (?, ?, ?)",
	postgres: "INSERT INTO web_origins (created_at, origin, client_id) VALUES ($1, $2, $3) RETURNING id",
	mssql:    "INSERT INTO web_origins (created_at, origin, client_id) OUTPUT INSERTED.id VALUES (@p1, @p2, @p3)",
}

var selectWebOriginById = statement{
	sqlite:   "SELECT " + webOriginColumns.sqlite + " FROM web_origins WHERE id = ?",
	mysql:    "SELECT " + webOriginColumns.mysql + " FROM web_origins WHERE id = ?",
	postgres: "SELECT " + webOriginColumns.postgres + " FROM web_origins WHERE id = $1",
	mssql:    "SELECT " + webOriginColumns.mssql + " FROM web_origins WHERE id = @p1",
}

var selectWebOriginsByClientId = statement{
	sqlite:   "SELECT " + webOriginColumns.sqlite + " FROM web_origins WHERE client_id = ?",
	mysql:    "SELECT " + webOriginColumns.mysql + " FROM web_origins WHERE client_id = ?",
	postgres: "SELECT " + webOriginColumns.postgres + " FROM web_origins WHERE client_id = $1",
	mssql:    "SELECT " + webOriginColumns.mssql + " FROM web_origins WHERE client_id = @p1",
}

var selectAllWebOrigins = statement{
	sqlite:   "SELECT " + webOriginColumns.sqlite + " FROM web_origins",
	mysql:    "SELECT " + webOriginColumns.mysql + " FROM web_origins",
	postgres: "SELECT " + webOriginColumns.postgres + " FROM web_origins",
	mssql:    "SELECT " + webOriginColumns.mssql + " FROM web_origins",
}

var countWebOriginsByOrigin = statement{
	sqlite:   "SELECT count(*) FROM web_origins WHERE origin = ?",
	mysql:    "SELECT count(*) FROM web_origins WHERE origin = ?",
	postgres: "SELECT count(*) FROM web_origins WHERE origin = $1",
	mssql:    "SELECT count(*) FROM web_origins WHERE origin = @p1",
}

var deleteWebOrigin = statement{
	sqlite:   "DELETE FROM web_origins WHERE id = ?",
	mysql:    "DELETE FROM web_origins WHERE id = ?",
	postgres: "DELETE FROM web_origins WHERE id = $1",
	mssql:    "DELETE FROM web_origins WHERE id = @p1",
}

func (d *Database) CreateWebOrigin(ctx context.Context, tx *sql.Tx, webOrigin *record.WebOrigin) error {

	if webOrigin.ClientId == 0 {
		return errs.New("client id must be greater than 0")
	}

	now := time.Now().UTC()

	originalCreatedAt := webOrigin.CreatedAt
	webOrigin.CreatedAt = sql.NullTime{Time: now, Valid: true}

	id, err := d.insert(ctx, tx, insertWebOrigin, "webOrigin",
		webOrigin.CreatedAt, webOrigin.Origin, webOrigin.ClientId)
	if err != nil {
		webOrigin.CreatedAt = originalCreatedAt
		return err
	}

	webOrigin.Id = id
	return nil
}

func (d *Database) GetWebOriginById(ctx context.Context, tx *sql.Tx, webOriginId int64) (*record.WebOrigin, error) {
	return queryOne(ctx, d, tx, selectWebOriginById.text(d.Dialect), []any{webOriginId}, scanWebOrigin, "webOrigin")
}

func (d *Database) GetWebOriginsByClientId(ctx context.Context, tx *sql.Tx, clientId int64) ([]record.WebOrigin, error) {
	return queryAll(ctx, d, tx, nil, selectWebOriginsByClientId.text(d.Dialect), []any{clientId},
		scanWebOrigin, "webOrigin")
}

func (d *Database) GetAllWebOrigins(ctx context.Context, tx *sql.Tx) ([]record.WebOrigin, error) {
	return queryAll(ctx, d, tx, nil, selectAllWebOrigins.text(d.Dialect), nil, scanWebOrigin, "webOrigin")
}

// WebOriginExists reports whether any client has registered origin. It answers the CORS
// middleware's only question, which is server-wide rather than per client: a browser's
// preflight carries no client identity, so there is nothing to scope the lookup to (#250).
//
// It exists to replace a full read of web_origins on every CORS-checked request. The unique
// index on (origin, client_id) that migration 000034 adds is origin-leading precisely so this
// count is an index lookup rather than a scan.
//
// The rows.Err() check is not boilerplate. This method gates cross-origin access, so a query
// that failed part way through and reported false would fail closed with no explanation, and
// one that reported true would fail open; either way every mock-backed test above stays green.
func (d *Database) WebOriginExists(ctx context.Context, tx *sql.Tx, origin string) (bool, error) {

	rows, err := d.QuerySQL(ctx, tx, countWebOriginsByOrigin.text(d.Dialect), origin)
	if err != nil {
		return false, errs.Wrap(err, "unable to query database")
	}
	defer func() { _ = rows.Close() }()

	var count int
	if rows.Next() {
		if err := rows.Scan(&count); err != nil {
			return false, errs.Wrap(err, "unable to scan web origin count")
		}
	}

	if err := rows.Err(); err != nil {
		return false, errs.Wrap(err, "unable to read query results")
	}

	return count > 0, nil
}

func (d *Database) DeleteWebOrigin(ctx context.Context, tx *sql.Tx, webOriginId int64) error {

	_, err := d.ExecSQL(ctx, tx, deleteWebOrigin.text(d.Dialect), webOriginId)
	if err != nil {
		return errs.Wrap(err, "unable to delete webOrigin")
	}

	return nil
}
