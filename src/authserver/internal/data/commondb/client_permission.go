package commondb

import (
	"context"
	"database/sql"
	"time"

	"github.com/huandu/go-sqlbuilder"
	"github.com/leodip/goiabada/authserver/internal/models"
	"github.com/leodip/goiabada/core/errs"
)

func (d *CommonDatabase) CreateClientPermission(ctx context.Context, tx *sql.Tx, clientPermission *models.ClientPermission) error {

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

	clientPermissionStruct := sqlbuilder.NewStruct(new(models.ClientPermission)).
		For(d.Flavor)

	insertBuilder := clientPermissionStruct.WithoutTag("pk").InsertInto("clients_permissions", clientPermission)

	id, err := d.insertReturningId(ctx, tx, insertBuilder, "clientPermission")
	if err != nil {
		clientPermission.CreatedAt = originalCreatedAt
		clientPermission.UpdatedAt = originalUpdatedAt
		return err
	}

	clientPermission.Id = id
	return nil
}

func (d *CommonDatabase) UpdateClientPermission(ctx context.Context, tx *sql.Tx, clientPermission *models.ClientPermission) error {

	if clientPermission.Id == 0 {
		return errs.New("can't update clientPermission with id 0")
	}

	originalUpdatedAt := clientPermission.UpdatedAt
	clientPermission.UpdatedAt = sql.NullTime{Time: time.Now().UTC(), Valid: true}

	clientPermissionStruct := sqlbuilder.NewStruct(new(models.ClientPermission)).
		For(d.Flavor)

	updateBuilder := clientPermissionStruct.WithoutTag("pk").WithoutTag("dont-update").Update("clients_permissions", clientPermission)
	updateBuilder.Where(updateBuilder.Equal("id", clientPermission.Id))

	sql, args := updateBuilder.Build()
	_, err := d.ExecSql(ctx, tx, sql, args...)
	if err != nil {
		clientPermission.UpdatedAt = originalUpdatedAt
		return errs.Wrap(err, "unable to update clientPermission")
	}

	return nil
}

func (d *CommonDatabase) getClientPermissionCommon(ctx context.Context, tx *sql.Tx, selectBuilder *sqlbuilder.SelectBuilder,
	clientPermissionStruct *sqlbuilder.Struct) (*models.ClientPermission, error) {

	sql, args := selectBuilder.Build()
	rows, err := d.QuerySql(ctx, tx, sql, args...)
	if err != nil {
		return nil, errs.Wrap(err, "unable to query database")
	}
	defer func() { _ = rows.Close() }()

	var clientPermission models.ClientPermission
	if rows.Next() {
		addr := clientPermissionStruct.Addr(&clientPermission)
		err = rows.Scan(addr...)
		if err != nil {
			return nil, errs.Wrap(err, "unable to scan clientPermission")
		}
		return &clientPermission, nil
	}
	if err := rows.Err(); err != nil {
		return nil, errs.Wrap(err, "unable to read query results")
	}

	return nil, nil
}

func (d *CommonDatabase) GetClientPermissionById(ctx context.Context, tx *sql.Tx, clientPermissionId int64) (*models.ClientPermission, error) {

	clientPermissionStruct := sqlbuilder.NewStruct(new(models.ClientPermission)).
		For(d.Flavor)

	selectBuilder := clientPermissionStruct.SelectFrom("clients_permissions")
	selectBuilder.Where(selectBuilder.Equal("id", clientPermissionId))

	clientPermission, err := d.getClientPermissionCommon(ctx, tx, selectBuilder, clientPermissionStruct)
	if err != nil {
		return nil, err
	}

	return clientPermission, nil
}

func (d *CommonDatabase) GetClientPermissionByClientIdAndPermissionId(ctx context.Context, tx *sql.Tx, clientId, permissionId int64) (*models.ClientPermission, error) {

	clientPermissionStruct := sqlbuilder.NewStruct(new(models.ClientPermission)).
		For(d.Flavor)

	selectBuilder := clientPermissionStruct.SelectFrom("clients_permissions")
	selectBuilder.Where(selectBuilder.Equal("client_id", clientId))
	selectBuilder.Where(selectBuilder.Equal("permission_id", permissionId))

	clientPermission, err := d.getClientPermissionCommon(ctx, tx, selectBuilder, clientPermissionStruct)
	if err != nil {
		return nil, err
	}

	return clientPermission, nil
}

func (d *CommonDatabase) GetClientPermissionsByClientId(ctx context.Context, tx *sql.Tx, clientId int64) ([]models.ClientPermission, error) {

	clientPermissionStruct := sqlbuilder.NewStruct(new(models.ClientPermission)).
		For(d.Flavor)

	selectBuilder := clientPermissionStruct.SelectFrom("clients_permissions")
	selectBuilder.Where(selectBuilder.Equal("client_id", clientId))

	sql, args := selectBuilder.Build()
	rows, err := d.QuerySql(ctx, tx, sql, args...)
	if err != nil {
		return nil, errs.Wrap(err, "unable to query database")
	}
	defer func() { _ = rows.Close() }()

	var clientPermissions []models.ClientPermission
	for rows.Next() {
		var clientPermission models.ClientPermission
		addr := clientPermissionStruct.Addr(&clientPermission)
		err = rows.Scan(addr...)
		if err != nil {
			return nil, errs.Wrap(err, "unable to scan clientPermission")
		}
		clientPermissions = append(clientPermissions, clientPermission)
	}

	if err := rows.Err(); err != nil {
		return nil, errs.Wrap(err, "unable to read query results")
	}

	return clientPermissions, nil
}

func (d *CommonDatabase) DeleteClientPermission(ctx context.Context, tx *sql.Tx, clientPermissionId int64) error {

	clientStruct := sqlbuilder.NewStruct(new(models.ClientPermission)).
		For(d.Flavor)

	deleteBuilder := clientStruct.DeleteFrom("clients_permissions")
	deleteBuilder.Where(deleteBuilder.Equal("id", clientPermissionId))

	sql, args := deleteBuilder.Build()
	_, err := d.ExecSql(ctx, tx, sql, args...)
	if err != nil {
		return errs.Wrap(err, "unable to delete clientPermission")
	}

	return nil
}
