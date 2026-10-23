package commondb

import (
	"context"
	"database/sql"
	"time"

	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/errs"
)

// clientLogoColumns is the client_logos table as scanClientLogo reads it.
var clientLogoColumns = columnList{
	sqlite:   "id, created_at, updated_at, client_id, logo, content_type",
	mysql:    "id, created_at, updated_at, client_id, logo, content_type",
	postgres: "id, created_at, updated_at, client_id, logo, content_type",
	mssql:    "id, created_at, updated_at, client_id, logo, content_type",
}

// scanClientLogo reads one row selected with clientLogoColumns.
func scanClientLogo(row rowScanner, clientLogo *record.ClientLogo) error {
	return row.Scan(
		&clientLogo.Id,
		&clientLogo.CreatedAt,
		&clientLogo.UpdatedAt,
		&clientLogo.ClientId,
		&clientLogo.Logo,
		&clientLogo.ContentType,
	)
}

var insertClientLogo = statement{
	sqlite:   "INSERT INTO client_logos (created_at, updated_at, client_id, logo, content_type) VALUES (?, ?, ?, ?, ?)",
	mysql:    "INSERT INTO client_logos (created_at, updated_at, client_id, logo, content_type) VALUES (?, ?, ?, ?, ?)",
	postgres: "INSERT INTO client_logos (created_at, updated_at, client_id, logo, content_type) VALUES ($1, $2, $3, $4, $5) RETURNING id",
	mssql:    "INSERT INTO client_logos (created_at, updated_at, client_id, logo, content_type) OUTPUT INSERTED.id VALUES (@p1, @p2, @p3, @p4, @p5)",
}

// updateClientLogo writes the whole row but created_at, which is dont-update.
var updateClientLogo = statement{
	sqlite:   "UPDATE client_logos SET updated_at = ?, client_id = ?, logo = ?, content_type = ? WHERE id = ?",
	mysql:    "UPDATE client_logos SET updated_at = ?, client_id = ?, logo = ?, content_type = ? WHERE id = ?",
	postgres: "UPDATE client_logos SET updated_at = $1, client_id = $2, logo = $3, content_type = $4 WHERE id = $5",
	mssql:    "UPDATE client_logos SET updated_at = @p1, client_id = @p2, logo = @p3, content_type = @p4 WHERE id = @p5",
}

var selectClientLogoByClientId = statement{
	sqlite:   "SELECT " + clientLogoColumns.sqlite + " FROM client_logos WHERE client_id = ?",
	mysql:    "SELECT " + clientLogoColumns.mysql + " FROM client_logos WHERE client_id = ?",
	postgres: "SELECT " + clientLogoColumns.postgres + " FROM client_logos WHERE client_id = $1",
	mssql:    "SELECT " + clientLogoColumns.mssql + " FROM client_logos WHERE client_id = @p1",
}

var deleteClientLogo = statement{
	sqlite:   "DELETE FROM client_logos WHERE client_id = ?",
	mysql:    "DELETE FROM client_logos WHERE client_id = ?",
	postgres: "DELETE FROM client_logos WHERE client_id = $1",
	mssql:    "DELETE FROM client_logos WHERE client_id = @p1",
}

// selectClientHasLogo reads at most one row. SQL Server pages with OFFSET … FETCH, which it accepts
// only after an ORDER BY.
var selectClientHasLogo = statement{
	sqlite:   "SELECT 1 FROM client_logos WHERE client_id = ? LIMIT 1",
	mysql:    "SELECT 1 FROM client_logos WHERE client_id = ? LIMIT 1",
	postgres: "SELECT 1 FROM client_logos WHERE client_id = $1 LIMIT 1",
	mssql:    "SELECT 1 FROM client_logos WHERE client_id = @p1 ORDER BY 1 OFFSET 0 ROWS FETCH NEXT 1 ROWS ONLY",
}

func (d *Database) CreateClientLogo(ctx context.Context, tx *sql.Tx, clientLogo *record.ClientLogo) error {

	if clientLogo.ClientId == 0 {
		return errs.New("can't create client logo with client_id 0")
	}

	now := time.Now().UTC()

	originalCreatedAt := clientLogo.CreatedAt
	originalUpdatedAt := clientLogo.UpdatedAt
	clientLogo.CreatedAt = sql.NullTime{Time: now, Valid: true}
	clientLogo.UpdatedAt = sql.NullTime{Time: now, Valid: true}

	id, err := d.insert(ctx, tx, insertClientLogo, "client logo",
		clientLogo.CreatedAt, clientLogo.UpdatedAt, clientLogo.ClientId, clientLogo.Logo, clientLogo.ContentType)
	if err != nil {
		clientLogo.CreatedAt = originalCreatedAt
		clientLogo.UpdatedAt = originalUpdatedAt
		return err
	}

	clientLogo.Id = id
	return nil
}

func (d *Database) UpdateClientLogo(ctx context.Context, tx *sql.Tx, clientLogo *record.ClientLogo) error {

	if clientLogo.Id == 0 {
		return errs.New("can't update client logo with id 0")
	}

	originalUpdatedAt := clientLogo.UpdatedAt
	clientLogo.UpdatedAt = sql.NullTime{Time: time.Now().UTC(), Valid: true}

	_, err := d.ExecSQL(ctx, tx, updateClientLogo.text(d.Dialect),
		clientLogo.UpdatedAt, clientLogo.ClientId, clientLogo.Logo, clientLogo.ContentType,
		clientLogo.Id)
	if err != nil {
		clientLogo.UpdatedAt = originalUpdatedAt
		return errs.Wrap(err, "unable to update client logo")
	}

	return nil
}

func (d *Database) GetClientLogoByClientId(ctx context.Context, tx *sql.Tx, clientId int64) (*record.ClientLogo, error) {
	return queryOne(ctx, d, tx, selectClientLogoByClientId.text(d.Dialect), []any{clientId}, scanClientLogo, "client logo")
}

func (d *Database) DeleteClientLogo(ctx context.Context, tx *sql.Tx, clientId int64) error {

	_, err := d.ExecSQL(ctx, tx, deleteClientLogo.text(d.Dialect), clientId)
	if err != nil {
		return errs.Wrap(err, "unable to delete client logo")
	}

	return nil
}

func (d *Database) ClientHasLogo(ctx context.Context, tx *sql.Tx, clientId int64) (bool, error) {

	rows, err := d.QuerySQL(ctx, tx, selectClientHasLogo.text(d.Dialect), clientId)
	if err != nil {
		return false, errs.Wrap(err, "unable to query database")
	}
	defer func() { _ = rows.Close() }()

	exists := rows.Next()
	if err := rows.Err(); err != nil {
		return false, errs.Wrap(err, "unable to read query results")
	}

	return exists, nil
}
