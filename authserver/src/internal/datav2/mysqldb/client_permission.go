package mysqldb

import (
	"database/sql"
	"time"

	"github.com/huandu/go-sqlbuilder"
	"github.com/leodip/goiabada/internal/entitiesv2"
	"github.com/pkg/errors"
)

func (d *MySQLDatabase) CreateClientPermission(tx *sql.Tx, clientPermission *entitiesv2.ClientPermission) error {

	if clientPermission.ClientId == 0 {
		return errors.New("can't create clientPermission with client_id 0")
	}

	if clientPermission.PermissionId == 0 {
		return errors.New("can't create clientPermission with permission_id 0")
	}

	now := time.Now().UTC()

	originalCreatedAt := clientPermission.CreatedAt
	originalUpdatedAt := clientPermission.UpdatedAt
	clientPermission.CreatedAt = sql.NullTime{Time: now, Valid: true}
	clientPermission.UpdatedAt = sql.NullTime{Time: now, Valid: true}

	clientPermissionStruct := sqlbuilder.NewStruct(new(entitiesv2.ClientPermission)).
		For(sqlbuilder.MySQL)

	insertBuilder := clientPermissionStruct.WithoutTag("pk").InsertInto("clients_permissions", clientPermission)

	sql, args := insertBuilder.Build()
	result, err := d.execSql(tx, sql, args...)
	if err != nil {
		clientPermission.CreatedAt = originalCreatedAt
		clientPermission.UpdatedAt = originalUpdatedAt
		return errors.Wrap(err, "unable to insert clientPermission")
	}

	id, err := result.LastInsertId()
	if err != nil {
		clientPermission.CreatedAt = originalCreatedAt
		clientPermission.UpdatedAt = originalUpdatedAt
		return errors.Wrap(err, "unable to get last insert id")
	}

	clientPermission.Id = id
	return nil
}

func (d *MySQLDatabase) UpdateClientPermission(tx *sql.Tx, clientPermission *entitiesv2.ClientPermission) error {

	if clientPermission.Id == 0 {
		return errors.New("can't update clientPermission with id 0")
	}

	originalUpdatedAt := clientPermission.UpdatedAt
	clientPermission.UpdatedAt = sql.NullTime{Time: time.Now().UTC(), Valid: true}

	clientPermissionStruct := sqlbuilder.NewStruct(new(entitiesv2.ClientPermission)).
		For(sqlbuilder.MySQL)

	updateBuilder := clientPermissionStruct.WithoutTag("pk").Update("clients_permissions", clientPermission)
	updateBuilder.Where(updateBuilder.Equal("id", clientPermission.Id))

	sql, args := updateBuilder.Build()
	_, err := d.execSql(tx, sql, args...)
	if err != nil {
		clientPermission.UpdatedAt = originalUpdatedAt
		return errors.Wrap(err, "unable to update clientPermission")
	}

	return nil
}

func (d *MySQLDatabase) getClientPermissionCommon(tx *sql.Tx, selectBuilder *sqlbuilder.SelectBuilder,
	clientPermissionStruct *sqlbuilder.Struct) (*entitiesv2.ClientPermission, error) {

	sql, args := selectBuilder.Build()
	rows, err := d.querySql(tx, sql, args...)
	if err != nil {
		return nil, errors.Wrap(err, "unable to query database")
	}
	defer rows.Close()

	var clientPermission entitiesv2.ClientPermission
	if rows.Next() {
		addr := clientPermissionStruct.Addr(&clientPermission)
		err = rows.Scan(addr...)
		if err != nil {
			return nil, errors.Wrap(err, "unable to scan clientPermission")
		}
		return &clientPermission, nil
	}
	return nil, nil
}

func (d *MySQLDatabase) GetClientPermissionById(tx *sql.Tx, clientPermissionId int64) (*entitiesv2.ClientPermission, error) {

	clientPermissionStruct := sqlbuilder.NewStruct(new(entitiesv2.ClientPermission)).
		For(sqlbuilder.MySQL)

	selectBuilder := clientPermissionStruct.SelectFrom("clients_permissions")
	selectBuilder.Where(selectBuilder.Equal("id", clientPermissionId))

	clientPermission, err := d.getClientPermissionCommon(tx, selectBuilder, clientPermissionStruct)
	if err != nil {
		return nil, err
	}

	return clientPermission, nil
}

func (d *MySQLDatabase) GetClientPermissionByClientIdAndPermissionId(tx *sql.Tx, clientId, permissionId int64) (*entitiesv2.ClientPermission, error) {

	clientPermissionStruct := sqlbuilder.NewStruct(new(entitiesv2.ClientPermission)).
		For(sqlbuilder.MySQL)

	selectBuilder := clientPermissionStruct.SelectFrom("clients_permissions")
	selectBuilder.Where(selectBuilder.Equal("client_id", clientId))
	selectBuilder.Where(selectBuilder.Equal("permission_id", permissionId))

	clientPermission, err := d.getClientPermissionCommon(tx, selectBuilder, clientPermissionStruct)
	if err != nil {
		return nil, err
	}

	return clientPermission, nil
}

func (d *MySQLDatabase) GetClientPermissionsByClientId(tx *sql.Tx, clientId int64) ([]entitiesv2.ClientPermission, error) {

	clientPermissionStruct := sqlbuilder.NewStruct(new(entitiesv2.ClientPermission)).
		For(sqlbuilder.MySQL)

	selectBuilder := clientPermissionStruct.SelectFrom("clients_permissions")
	selectBuilder.Where(selectBuilder.Equal("client_id", clientId))

	sql, args := selectBuilder.Build()
	rows, err := d.querySql(tx, sql, args...)
	if err != nil {
		return nil, errors.Wrap(err, "unable to query database")
	}
	defer rows.Close()

	var clientPermissions []entitiesv2.ClientPermission
	for rows.Next() {
		var clientPermission entitiesv2.ClientPermission
		addr := clientPermissionStruct.Addr(&clientPermission)
		err = rows.Scan(addr...)
		if err != nil {
			return nil, errors.Wrap(err, "unable to scan clientPermission")
		}
		clientPermissions = append(clientPermissions, clientPermission)
	}

	return clientPermissions, nil
}

func (d *MySQLDatabase) DeleteClientPermission(tx *sql.Tx, clientPermissionId int64) error {

	clientStruct := sqlbuilder.NewStruct(new(entitiesv2.ClientPermission)).
		For(sqlbuilder.MySQL)

	deleteBuilder := clientStruct.DeleteFrom("clients_permissions")
	deleteBuilder.Where(deleteBuilder.Equal("id", clientPermissionId))

	sql, args := deleteBuilder.Build()
	_, err := d.execSql(tx, sql, args...)
	if err != nil {
		return errors.Wrap(err, "unable to delete clientPermission")
	}

	return nil
}
