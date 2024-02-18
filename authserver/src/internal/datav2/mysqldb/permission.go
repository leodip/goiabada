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
	permission.CreatedAt = sql.NullTime{Time: now, Valid: true}
	permission.UpdatedAt = sql.NullTime{Time: now, Valid: true}

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
	permission.UpdatedAt = sql.NullTime{Time: time.Now().UTC(), Valid: true}

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
		err = rows.Scan(addr...)
		if err != nil {
			return nil, errors.Wrap(err, "unable to scan permission")
		}
		return &permission, nil
	}
	return nil, nil
}

func (d *MySQLDatabase) GetPermissionById(tx *sql.Tx, permissionId int64) (*entitiesv2.Permission, error) {

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

func (d *MySQLDatabase) GetPermissionsByResourceId(tx *sql.Tx, resourceId int64) ([]entitiesv2.Permission, error) {

	permissionStruct := sqlbuilder.NewStruct(new(entitiesv2.Permission)).
		For(sqlbuilder.MySQL)

	selectBuilder := permissionStruct.SelectFrom("permissions")
	selectBuilder.Where(selectBuilder.Equal("resource_id", resourceId))

	sql, args := selectBuilder.Build()
	rows, err := d.querySql(tx, sql, args...)
	if err != nil {
		return nil, errors.Wrap(err, "unable to query database")
	}
	defer rows.Close()

	var permissions []entitiesv2.Permission
	for rows.Next() {
		var permission entitiesv2.Permission
		addr := permissionStruct.Addr(&permission)
		err = rows.Scan(addr...)
		if err != nil {
			return nil, errors.Wrap(err, "unable to scan permission")
		}
		permissions = append(permissions, permission)
	}

	return permissions, nil
}

func (d *MySQLDatabase) PermissionsLoadResources(tx *sql.Tx, permissions []entitiesv2.Permission) error {

	if permissions == nil {
		return nil
	}

	resourceIds := make([]int64, 0, len(permissions))
	for _, permission := range permissions {
		resourceIds = append(resourceIds, permission.ResourceId)
	}

	resources, err := d.GetResourcesByIds(tx, resourceIds)
	if err != nil {
		return errors.Wrap(err, "unable to get resources for permissions")
	}

	resourceMap := make(map[int64]entitiesv2.Resource, len(resources))
	for _, resource := range resources {
		resourceMap[resource.Id] = resource
	}

	for i := range permissions {
		permissions[i].Resource = resourceMap[permissions[i].ResourceId]
	}

	return nil
}

func (d *MySQLDatabase) GetPermissionsByIds(tx *sql.Tx, permissionIds []int64) ([]entitiesv2.Permission, error) {

	permissionStruct := sqlbuilder.NewStruct(new(entitiesv2.Permission)).
		For(sqlbuilder.MySQL)

	selectBuilder := permissionStruct.SelectFrom("permissions")
	selectBuilder.Where(selectBuilder.In("id", permissionIds))

	sql, args := selectBuilder.Build()
	rows, err := d.querySql(tx, sql, args...)
	if err != nil {
		return nil, errors.Wrap(err, "unable to query database")
	}
	defer rows.Close()

	var permissions []entitiesv2.Permission
	for rows.Next() {
		var permission entitiesv2.Permission
		addr := permissionStruct.Addr(&permission)
		err = rows.Scan(addr...)
		if err != nil {
			return nil, errors.Wrap(err, "unable to scan permission")
		}
		permissions = append(permissions, permission)
	}

	return permissions, nil
}

func (d *MySQLDatabase) DeletePermission(tx *sql.Tx, permissionId int64) error {

	clientStruct := sqlbuilder.NewStruct(new(entitiesv2.Permission)).
		For(sqlbuilder.MySQL)

	deleteBuilder := clientStruct.DeleteFrom("permissions")
	deleteBuilder.Where(deleteBuilder.Equal("id", permissionId))

	sql, args := deleteBuilder.Build()
	_, err := d.execSql(tx, sql, args...)
	if err != nil {
		return errors.Wrap(err, "unable to delete permission")
	}

	return nil
}
