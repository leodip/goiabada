package mysqldb

import (
	"database/sql"
	"time"

	"github.com/huandu/go-sqlbuilder"
	"github.com/leodip/goiabada/internal/entitiesv2"
	"github.com/pkg/errors"
)

func (d *MySQLDatabase) CreatePermission(tx *sql.Tx, permission *entitiesv2.Permission) error {

	if permission.ResourceId == 0 {
		return errors.New("can't create permission with resource_id 0")
	}

	now := time.Now().UTC()

	originalCreatedAt := permission.CreatedAt
	originalUpdatedAt := permission.UpdatedAt
	permission.CreatedAt = now
	permission.UpdatedAt = now

	permissionStruct := sqlbuilder.NewStruct(new(entitiesv2.Permission)).
		For(sqlbuilder.MySQL)

	insertBuilder := permissionStruct.WithoutTag("pk").InsertInto("permissions", permission)

	sql, args := insertBuilder.Build()
	result, err := d.execSql(tx, sql, args...)
	if err != nil {
		permission.CreatedAt = originalCreatedAt
		permission.UpdatedAt = originalUpdatedAt
		return errors.Wrap(err, "unable to insert permission")
	}

	id, err := result.LastInsertId()
	if err != nil {
		permission.CreatedAt = originalCreatedAt
		permission.UpdatedAt = originalUpdatedAt
		return errors.Wrap(err, "unable to get last insert id")
	}

	permission.Id = id
	return nil
}

func (d *MySQLDatabase) UpdatePermission(tx *sql.Tx, permission *entitiesv2.Permission) error {

	if permission.Id == 0 {
		return errors.New("can't update permission with id 0")
	}

	originalUpdatedAt := permission.UpdatedAt
	permission.UpdatedAt = time.Now().UTC()

	permissionStruct := sqlbuilder.NewStruct(new(entitiesv2.Permission)).
		For(sqlbuilder.MySQL)

	updateBuilder := permissionStruct.WithoutTag("pk").Update("permissions", permission)
	updateBuilder.Where(updateBuilder.Equal("id", permission.Id))

	sql, args := updateBuilder.Build()
	_, err := d.execSql(tx, sql, args...)
	if err != nil {
		permission.UpdatedAt = originalUpdatedAt
		return errors.Wrap(err, "unable to update permission")
	}

	return nil
}

func (d *MySQLDatabase) getPermissionCommon(tx *sql.Tx, selectBuilder *sqlbuilder.SelectBuilder,
	permissionStruct *sqlbuilder.Struct) (*entitiesv2.Permission, error) {

	sql, args := selectBuilder.Build()
	rows, err := d.querySql(tx, sql, args...)
	if err != nil {
		return nil, errors.Wrap(err, "unable to query database")
	}
	defer rows.Close()

	var permission entitiesv2.Permission
	if rows.Next() {
		addr := permissionStruct.Addr(&permission)
		rows.Scan(addr...)
		return &permission, nil
	}
	return nil, nil
}

func (d *MySQLDatabase) GetPermissionById(tx *sql.Tx, permissionId int64) (*entitiesv2.Permission, error) {

	if permissionId <= 0 {
		return nil, errors.New("permission id must be greater than 0")
	}

	permissionStruct := sqlbuilder.NewStruct(new(entitiesv2.Permission)).
		For(sqlbuilder.MySQL)

	selectBuilder := permissionStruct.SelectFrom("permissions")
	selectBuilder.Where(selectBuilder.Equal("id", permissionId))

	permission, err := d.getPermissionCommon(tx, selectBuilder, permissionStruct)
	if err != nil {
		return nil, err
	}

	return permission, nil
}

func (d *MySQLDatabase) GetPermissionByPermissionIdentifier(tx *sql.Tx, permissionIdentifier string) (*entitiesv2.Permission, error) {

	if permissionIdentifier == "" {
		return nil, errors.New("permission identifier must be set")
	}

	permissionStruct := sqlbuilder.NewStruct(new(entitiesv2.Permission)).
		For(sqlbuilder.MySQL)

	selectBuilder := permissionStruct.SelectFrom("permissions")
	selectBuilder.Where(selectBuilder.Equal("permission_identifier", permissionIdentifier))

	permission, err := d.getPermissionCommon(tx, selectBuilder, permissionStruct)
	if err != nil {
		return nil, err
	}

	return permission, nil
}
