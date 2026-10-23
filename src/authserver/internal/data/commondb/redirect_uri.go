package commondb

import (
	"context"
	"database/sql"
	"time"

	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/errs"
)

// redirectURIColumns is the redirect_uris table as scanRedirectURI reads it.
var redirectURIColumns = columnList{
	sqlite:   "id, created_at, uri, client_id",
	mysql:    "id, created_at, uri, client_id",
	postgres: "id, created_at, uri, client_id",
	mssql:    "id, created_at, uri, client_id",
}

// scanRedirectURI reads one row selected with redirectURIColumns.
func scanRedirectURI(row rowScanner, redirectURI *record.RedirectURI) error {
	return row.Scan(
		&redirectURI.Id,
		&redirectURI.CreatedAt,
		&redirectURI.URI,
		&redirectURI.ClientId,
	)
}

var insertRedirectURI = statement{
	sqlite:   "INSERT INTO redirect_uris (created_at, uri, client_id) VALUES (?, ?, ?)",
	mysql:    "INSERT INTO redirect_uris (created_at, uri, client_id) VALUES (?, ?, ?)",
	postgres: "INSERT INTO redirect_uris (created_at, uri, client_id) VALUES ($1, $2, $3) RETURNING id",
	mssql:    "INSERT INTO redirect_uris (created_at, uri, client_id) OUTPUT INSERTED.id VALUES (@p1, @p2, @p3)",
}

var selectRedirectURIById = statement{
	sqlite:   "SELECT " + redirectURIColumns.sqlite + " FROM redirect_uris WHERE id = ?",
	mysql:    "SELECT " + redirectURIColumns.mysql + " FROM redirect_uris WHERE id = ?",
	postgres: "SELECT " + redirectURIColumns.postgres + " FROM redirect_uris WHERE id = $1",
	mssql:    "SELECT " + redirectURIColumns.mssql + " FROM redirect_uris WHERE id = @p1",
}

var selectRedirectURIsByClientId = statement{
	sqlite:   "SELECT " + redirectURIColumns.sqlite + " FROM redirect_uris WHERE client_id = ?",
	mysql:    "SELECT " + redirectURIColumns.mysql + " FROM redirect_uris WHERE client_id = ?",
	postgres: "SELECT " + redirectURIColumns.postgres + " FROM redirect_uris WHERE client_id = $1",
	mssql:    "SELECT " + redirectURIColumns.mssql + " FROM redirect_uris WHERE client_id = @p1",
}

var deleteRedirectURI = statement{
	sqlite:   "DELETE FROM redirect_uris WHERE id = ?",
	mysql:    "DELETE FROM redirect_uris WHERE id = ?",
	postgres: "DELETE FROM redirect_uris WHERE id = $1",
	mssql:    "DELETE FROM redirect_uris WHERE id = @p1",
}

func (d *Database) CreateRedirectURI(ctx context.Context, tx *sql.Tx, redirectURI *record.RedirectURI) error {

	if redirectURI.ClientId == 0 {
		return errs.New("client id must be greater than 0")
	}

	now := time.Now().UTC()

	originalCreatedAt := redirectURI.CreatedAt
	redirectURI.CreatedAt = sql.NullTime{Time: now, Valid: true}

	id, err := d.insert(ctx, tx, insertRedirectURI, "redirectURI",
		redirectURI.CreatedAt, redirectURI.URI, redirectURI.ClientId)
	if err != nil {
		redirectURI.CreatedAt = originalCreatedAt
		return err
	}

	redirectURI.Id = id
	return nil
}

func (d *Database) GetRedirectURIById(ctx context.Context, tx *sql.Tx, redirectURIId int64) (*record.RedirectURI, error) {
	return queryOne(ctx, d, tx, selectRedirectURIById.text(d.Dialect), []any{redirectURIId}, scanRedirectURI, "redirectURI")
}

func (d *Database) GetRedirectURIsByClientId(ctx context.Context, tx *sql.Tx, clientId int64) ([]record.RedirectURI, error) {
	return queryAll(ctx, d, tx, []record.RedirectURI{}, selectRedirectURIsByClientId.text(d.Dialect), []any{clientId},
		scanRedirectURI, "redirectURI")
}

func (d *Database) DeleteRedirectURI(ctx context.Context, tx *sql.Tx, redirectURIId int64) error {

	_, err := d.ExecSQL(ctx, tx, deleteRedirectURI.text(d.Dialect), redirectURIId)
	if err != nil {
		return errs.Wrap(err, "unable to delete redirectURI")
	}

	return nil
}
