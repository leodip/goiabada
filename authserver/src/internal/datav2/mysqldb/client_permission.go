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
	clientPermission.CreatedAt = now
	clientPermission.UpdatedAt = now

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
	clientPermission.UpdatedAt = time.Now().UTC()

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
		rows.Scan(addr...)
		return &clientPermission, nil
	}
	return nil, nil
}

func (d *MySQLDatabase) GetClientPermissionById(tx *sql.Tx, clientPermissionId int64) (*entitiesv2.ClientPermission, error) {

	if clientPermissionId <= 0 {
		return nil, errors.New("clientPermission id must be greater than 0")
	}

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

func (d *MySQLDatabase) DeleteClientPermission(tx *sql.Tx, clientPermissionId int64) error {
	if clientPermissionId <= 0 {
		return errors.New("clientPermission id must be greater than 0")
	}

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
