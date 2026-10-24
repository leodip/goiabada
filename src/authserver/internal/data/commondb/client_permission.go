package commondb

import (
	"context"
	"database/sql"
	"time"

	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/errs"
)

// clientPermissionColumns is the clients_permissions table as scanClientPermission reads it.
var clientPermissionColumns = columnList{
	sqlite:   "id, created_at, updated_at, client_id, permission_id",
	mysql:    "id, created_at, updated_at, client_id, permission_id",
	postgres: "id, created_at, updated_at, client_id, permission_id",
	mssql:    "id, created_at, updated_at, client_id, permission_id",
}

// scanClientPermission reads one row selected with clientPermissionColumns.
func scanClientPermission(row rowScanner, clientPermission *record.ClientPermission) error {
	return row.Scan(
		&clientPermission.Id,
		&clientPermission.CreatedAt,
		&clientPermission.UpdatedAt,
		&clientPermission.ClientId,
		&clientPermission.PermissionId,
	)
}

var insertClientPermission = statement{
	sqlite:   "INSERT INTO clients_permissions (created_at, updated_at, client_id, permission_id) VALUES (?, ?, ?, ?)",
	mysql:    "INSERT INTO clients_permissions (created_at, updated_at, client_id, permission_id) VALUES (?, ?, ?, ?)",
	postgres: "INSERT INTO clients_permissions (created_at, updated_at, client_id, permission_id) VALUES ($1, $2, $3, $4) RETURNING id",
	mssql:    "INSERT INTO clients_permissions (created_at, updated_at, client_id, permission_id) OUTPUT INSERTED.id VALUES (@p1, @p2, @p3, @p4)",
}

// updateClientPermission writes the whole row but created_at, which is dont-update.
var updateClientPermission = statement{
	sqlite:   "UPDATE clients_permissions SET updated_at = ?, client_id = ?, permission_id = ? WHERE id = ?",
	mysql:    "UPDATE clients_permissions SET updated_at = ?, client_id = ?, permission_id = ? WHERE id = ?",
	postgres: "UPDATE clients_permissions SET updated_at = $1, client_id = $2, permission_id = $3 WHERE id = $4",
	mssql:    "UPDATE clients_permissions SET updated_at = @p1, client_id = @p2, permission_id = @p3 WHERE id = @p4",
}

var selectClientPermissionById = statement{
	sqlite:   "SELECT " + clientPermissionColumns.sqlite + " FROM clients_permissions WHERE id = ?",
	mysql:    "SELECT " + clientPermissionColumns.mysql + " FROM clients_permissions WHERE id = ?",
	postgres: "SELECT " + clientPermissionColumns.postgres + " FROM clients_permissions WHERE id = $1",
	mssql:    "SELECT " + clientPermissionColumns.mssql + " FROM clients_permissions WHERE id = @p1",
}

var selectClientPermissionByClientIdAndPermissionId = statement{
	sqlite:   "SELECT " + clientPermissionColumns.sqlite + " FROM clients_permissions WHERE client_id = ? AND permission_id = ?",
	mysql:    "SELECT " + clientPermissionColumns.mysql + " FROM clients_permissions WHERE client_id = ? AND permission_id = ?",
	postgres: "SELECT " + clientPermissionColumns.postgres + " FROM clients_permissions WHERE client_id = $1 AND permission_id = $2",
	mssql:    "SELECT " + clientPermissionColumns.mssql + " FROM clients_permissions WHERE client_id = @p1 AND permission_id = @p2",
}

var selectClientPermissionsByClientId = statement{
	sqlite:   "SELECT " + clientPermissionColumns.sqlite + " FROM clients_permissions WHERE client_id = ?",
	mysql:    "SELECT " + clientPermissionColumns.mysql + " FROM clients_permissions WHERE client_id = ?",
	postgres: "SELECT " + clientPermissionColumns.postgres + " FROM clients_permissions WHERE client_id = $1",
	mssql:    "SELECT " + clientPermissionColumns.mssql + " FROM clients_permissions WHERE client_id = @p1",
}

var deleteClientPermission = statement{
	sqlite:   "DELETE FROM clients_permissions WHERE id = ?",
	mysql:    "DELETE FROM clients_permissions WHERE id = ?",
	postgres: "DELETE FROM clients_permissions WHERE id = $1",
	mssql:    "DELETE FROM clients_permissions WHERE id = @p1",
}

func (d *Database) CreateClientPermission(ctx context.Context, tx *sql.Tx, clientPermission *record.ClientPermission) error {

	if clientPermission.ClientId == 0 {
		return errs.New("can't create clientPermission with client_id 0")
	}

	if clientPermission.PermissionId == 0 {
		return errs.New("can't create clientPermission with permission_id 0")
	}

	now := time.Now().UTC()

	originalCreatedAt := clientPermission.CreatedAt
	originalUpdatedAt := clientPermission.UpdatedAt
	clientPermission.CreatedAt = sql.NullTime{Time: now, Valid: true}
	clientPermission.UpdatedAt = sql.NullTime{Time: now, Valid: true}

	id, err := d.insert(ctx, tx, insertClientPermission, "clientPermission",
		clientPermission.CreatedAt, clientPermission.UpdatedAt, clientPermission.ClientId, clientPermission.PermissionId)
	if err != nil {
		clientPermission.CreatedAt = originalCreatedAt
		clientPermission.UpdatedAt = originalUpdatedAt
		return err
	}

	clientPermission.Id = id
	return nil
}

func (d *Database) UpdateClientPermission(ctx context.Context, tx *sql.Tx, clientPermission *record.ClientPermission) error {

	if clientPermission.Id == 0 {
		return errs.New("can't update clientPermission with id 0")
	}

	originalUpdatedAt := clientPermission.UpdatedAt
	clientPermission.UpdatedAt = sql.NullTime{Time: time.Now().UTC(), Valid: true}

	_, err := d.ExecSQL(ctx, tx, updateClientPermission.text(d.Dialect),
		clientPermission.UpdatedAt, clientPermission.ClientId, clientPermission.PermissionId,
		clientPermission.Id)
	if err != nil {
		clientPermission.UpdatedAt = originalUpdatedAt
		return errs.Wrap(err, "unable to update clientPermission")
	}

	return nil
}

func (d *Database) GetClientPermissionById(ctx context.Context, tx *sql.Tx, clientPermissionId int64) (*record.ClientPermission, error) {
	return queryOne(ctx, d, tx, selectClientPermissionById.text(d.Dialect), []any{clientPermissionId},
		scanClientPermission, "clientPermission")
}

func (d *Database) GetClientPermissionByClientIdAndPermissionId(ctx context.Context, tx *sql.Tx, clientId, permissionId int64) (*record.ClientPermission, error) {
	return queryOne(ctx, d, tx, selectClientPermissionByClientIdAndPermissionId.text(d.Dialect),
		[]any{clientId, permissionId}, scanClientPermission, "clientPermission")
}

func (d *Database) GetClientPermissionsByClientId(ctx context.Context, tx *sql.Tx, clientId int64) ([]record.ClientPermission, error) {
	return queryAll(ctx, d, tx, nil, selectClientPermissionsByClientId.text(d.Dialect), []any{clientId},
		scanClientPermission, "clientPermission")
}

func (d *Database) DeleteClientPermission(ctx context.Context, tx *sql.Tx, clientPermissionId int64) error {

	_, err := d.ExecSQL(ctx, tx, deleteClientPermission.text(d.Dialect), clientPermissionId)
	if err != nil {
		return errs.Wrap(err, "unable to delete clientPermission")
	}

	return nil
}
