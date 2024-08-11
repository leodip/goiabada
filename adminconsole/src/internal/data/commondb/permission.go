package commondb

import (
	"database/sql"
	"time"

	"github.com/huandu/go-sqlbuilder"
	"github.com/leodip/goiabada/adminconsole/internal/models"
	"github.com/pkg/errors"
)

func (d *CommonDatabase) CreatePermission(tx *sql.Tx, permission *models.Permission) error {

	if permission.ResourceId == 0 {
		return errors.WithStack(errors.New("can't create permission with resource_id 0"))
	}

	now := time.Now().UTC()

	originalCreatedAt := permission.CreatedAt
	originalUpdatedAt := permission.UpdatedAt
	permission.CreatedAt = sql.NullTime{Time: now, Valid: true}
	permission.UpdatedAt = sql.NullTime{Time: now, Valid: true}

	permissionStruct := sqlbuilder.NewStruct(new(models.Permission)).
		For(d.Flavor)

	insertBuilder := permissionStruct.WithoutTag("pk").InsertInto("permissions", permission)

	sql, args := insertBuilder.Build()
	result, err := d.ExecSql(tx, sql, args...)
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

func (d *CommonDatabase) UpdatePermission(tx *sql.Tx, permission *models.Permission) error {

	if permission.Id == 0 {
		return errors.WithStack(errors.New("can't update permission with id 0"))
	}

	originalUpdatedAt := permission.UpdatedAt
	permission.UpdatedAt = sql.NullTime{Time: time.Now().UTC(), Valid: true}

	permissionStruct := sqlbuilder.NewStruct(new(models.Permission)).
		For(d.Flavor)

	updateBuilder := permissionStruct.WithoutTag("pk").Update("permissions", permission)
	updateBuilder.Where(updateBuilder.Equal("id", permission.Id))

	sql, args := updateBuilder.Build()
	_, err := d.ExecSql(tx, sql, args...)
	if err != nil {
		permission.UpdatedAt = originalUpdatedAt
		return errors.Wrap(err, "unable to update permission")
	}

	return nil
}

func (d *CommonDatabase) getPermissionCommon(tx *sql.Tx, selectBuilder *sqlbuilder.SelectBuilder,
	permissionStruct *sqlbuilder.Struct) (*models.Permission, error) {

	sql, args := selectBuilder.Build()
	rows, err := d.QuerySql(tx, sql, args...)
	if err != nil {
		return nil, errors.Wrap(err, "unable to query database")
	}
	defer rows.Close()

	var permission models.Permission
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

func (d *CommonDatabase) GetPermissionById(tx *sql.Tx, permissionId int64) (*models.Permission, error) {

	permissionStruct := sqlbuilder.NewStruct(new(models.Permission)).
		For(d.Flavor)

	selectBuilder := permissionStruct.SelectFrom("permissions")
	selectBuilder.Where(selectBuilder.Equal("id", permissionId))

	permission, err := d.getPermissionCommon(tx, selectBuilder, permissionStruct)
	if err != nil {
		return nil, err
	}

	return permission, nil
}

func (d *CommonDatabase) GetPermissionsByResourceId(tx *sql.Tx, resourceId int64) ([]models.Permission, error) {

	permissionStruct := sqlbuilder.NewStruct(new(models.Permission)).
		For(d.Flavor)

	selectBuilder := permissionStruct.SelectFrom("permissions")
	selectBuilder.Where(selectBuilder.Equal("resource_id", resourceId))

	sql, args := selectBuilder.Build()
	rows, err := d.QuerySql(tx, sql, args...)
	if err != nil {
		return nil, errors.Wrap(err, "unable to query database")
	}
	defer rows.Close()

	var permissions []models.Permission
	for rows.Next() {
		var permission models.Permission
		addr := permissionStruct.Addr(&permission)
		err = rows.Scan(addr...)
		if err != nil {
			return nil, errors.Wrap(err, "unable to scan permission")
		}
		permissions = append(permissions, permission)
	}

	return permissions, nil
}

func (d *CommonDatabase) PermissionsLoadResources(tx *sql.Tx, permissions []models.Permission) error {

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

	resourceMap := make(map[int64]models.Resource, len(resources))
	for _, resource := range resources {
		resourceMap[resource.Id] = resource
	}

	for i := range permissions {
		permissions[i].Resource = resourceMap[permissions[i].ResourceId]
	}

	return nil
}

func (d *CommonDatabase) GetPermissionsByIds(tx *sql.Tx, permissionIds []int64) ([]models.Permission, error) {

	if len(permissionIds) == 0 {
		return nil, nil
	}

	permissionStruct := sqlbuilder.NewStruct(new(models.Permission)).
		For(d.Flavor)

	selectBuilder := permissionStruct.SelectFrom("permissions")
	selectBuilder.Where(selectBuilder.In("id", sqlbuilder.Flatten(permissionIds)...))

	sql, args := selectBuilder.Build()
	rows, err := d.QuerySql(tx, sql, args...)
	if err != nil {
		return nil, errors.Wrap(err, "unable to query database")
	}
	defer rows.Close()

	var permissions []models.Permission
	for rows.Next() {
		var permission models.Permission
		addr := permissionStruct.Addr(&permission)
		err = rows.Scan(addr...)
		if err != nil {
			return nil, errors.Wrap(err, "unable to scan permission")
		}
		permissions = append(permissions, permission)
	}

	return permissions, nil
}

func (d *CommonDatabase) DeletePermission(tx *sql.Tx, permissionId int64) error {

	clientStruct := sqlbuilder.NewStruct(new(models.Permission)).
		For(d.Flavor)

	deleteBuilder := clientStruct.DeleteFrom("permissions")
	deleteBuilder.Where(deleteBuilder.Equal("id", permissionId))

	sql, args := deleteBuilder.Build()
	_, err := d.ExecSql(tx, sql, args...)
	if err != nil {
		return errors.Wrap(err, "unable to delete permission")
	}

	return nil
}
