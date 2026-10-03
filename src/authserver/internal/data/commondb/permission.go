package commondb

import (
	"context"
	"database/sql"
	"time"

	"github.com/huandu/go-sqlbuilder"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/errs"
)

func (d *Database) CreatePermission(ctx context.Context, tx *sql.Tx, permission *record.Permission) error {

	if permission.ResourceId == 0 {
		return errs.New("can't create permission with resource_id 0")
	}

	now := time.Now().UTC()

	originalCreatedAt := permission.CreatedAt
	originalUpdatedAt := permission.UpdatedAt
	permission.CreatedAt = sql.NullTime{Time: now, Valid: true}
	permission.UpdatedAt = sql.NullTime{Time: now, Valid: true}

	permissionStruct := sqlbuilder.NewStruct(new(record.Permission)).
		For(d.Flavor)

	insertBuilder := permissionStruct.WithoutTag("pk").InsertInto("permissions", permission)

	id, err := d.insertReturningId(ctx, tx, insertBuilder, "permission")
	if err != nil {
		permission.CreatedAt = originalCreatedAt
		permission.UpdatedAt = originalUpdatedAt
		return err
	}

	permission.Id = id
	return nil
}

func (d *Database) UpdatePermission(ctx context.Context, tx *sql.Tx, permission *record.Permission) error {

	if permission.Id == 0 {
		return errs.New("can't update permission with id 0")
	}

	originalUpdatedAt := permission.UpdatedAt
	permission.UpdatedAt = sql.NullTime{Time: time.Now().UTC(), Valid: true}

	permissionStruct := sqlbuilder.NewStruct(new(record.Permission)).
		For(d.Flavor)

	updateBuilder := permissionStruct.WithoutTag("pk").WithoutTag("dont-update").Update("permissions", permission)
	updateBuilder.Where(updateBuilder.Equal("id", permission.Id))

	sql, args := updateBuilder.Build()
	_, err := d.ExecSQL(ctx, tx, sql, args...)
	if err != nil {
		permission.UpdatedAt = originalUpdatedAt
		return errs.Wrap(err, "unable to update permission")
	}

	return nil
}

func (d *Database) getPermissionCommon(ctx context.Context, tx *sql.Tx, selectBuilder *sqlbuilder.SelectBuilder,
	permissionStruct *sqlbuilder.Struct) (*record.Permission, error) {

	sql, args := selectBuilder.Build()
	rows, err := d.QuerySQL(ctx, tx, sql, args...)
	if err != nil {
		return nil, errs.Wrap(err, "unable to query database")
	}
	defer func() { _ = rows.Close() }()

	var permission record.Permission
	if rows.Next() {
		addr := permissionStruct.Addr(&permission)
		err = rows.Scan(addr...)
		if err != nil {
			return nil, errs.Wrap(err, "unable to scan permission")
		}
		return &permission, nil
	}
	if err := rows.Err(); err != nil {
		return nil, errs.Wrap(err, "unable to read query results")
	}

	return nil, nil
}

func (d *Database) GetPermissionById(ctx context.Context, tx *sql.Tx, permissionId int64) (*record.Permission, error) {

	permissionStruct := sqlbuilder.NewStruct(new(record.Permission)).
		For(d.Flavor)

	selectBuilder := permissionStruct.SelectFrom("permissions")
	selectBuilder.Where(selectBuilder.Equal("id", permissionId))

	permission, err := d.getPermissionCommon(ctx, tx, selectBuilder, permissionStruct)
	if err != nil {
		return nil, err
	}

	return permission, nil
}

func (d *Database) GetPermissionsByResourceId(ctx context.Context, tx *sql.Tx, resourceId int64) ([]record.Permission, error) {

	permissionStruct := sqlbuilder.NewStruct(new(record.Permission)).
		For(d.Flavor)

	selectBuilder := permissionStruct.SelectFrom("permissions")
	selectBuilder.Where(selectBuilder.Equal("resource_id", resourceId))

	sql, args := selectBuilder.Build()
	rows, err := d.QuerySQL(ctx, tx, sql, args...)
	if err != nil {
		return nil, errs.Wrap(err, "unable to query database")
	}
	defer func() { _ = rows.Close() }()

	var permissions []record.Permission
	for rows.Next() {
		var permission record.Permission
		addr := permissionStruct.Addr(&permission)
		err = rows.Scan(addr...)
		if err != nil {
			return nil, errs.Wrap(err, "unable to scan permission")
		}
		permissions = append(permissions, permission)
	}

	if err := rows.Err(); err != nil {
		return nil, errs.Wrap(err, "unable to read query results")
	}

	return permissions, nil
}

func (d *Database) PermissionsLoadResources(ctx context.Context, tx *sql.Tx, permissions []record.Permission) error {

	if permissions == nil {
		return nil
	}

	resourceIds := make([]int64, 0, len(permissions))
	for _, permission := range permissions {
		resourceIds = append(resourceIds, permission.ResourceId)
	}

	resources, err := d.GetResourcesByIds(ctx, tx, resourceIds)
	if err != nil {
		return errs.Wrap(err, "unable to get resources for permissions")
	}

	resourceMap := make(map[int64]record.Resource, len(resources))
	for _, resource := range resources {
		resourceMap[resource.Id] = resource
	}

	for i := range permissions {
		permissions[i].Resource = resourceMap[permissions[i].ResourceId]
	}

	return nil
}

func (d *Database) GetPermissionsByIds(ctx context.Context, tx *sql.Tx, permissionIds []int64) ([]record.Permission, error) {

	if len(permissionIds) == 0 {
		return nil, nil
	}

	var permissions []record.Permission

	err := forEachIdBatch(permissionIds, func(batch []int64) error {
		permissionStruct := sqlbuilder.NewStruct(new(record.Permission)).
			For(d.Flavor)

		selectBuilder := permissionStruct.SelectFrom("permissions")
		selectBuilder.Where(selectBuilder.In("id", sqlbuilder.Flatten(batch)...))

		sql, args := selectBuilder.Build()
		rows, err := d.QuerySQL(ctx, tx, sql, args...)
		if err != nil {
			return errs.Wrap(err, "unable to query database")
		}
		defer func() { _ = rows.Close() }()

		for rows.Next() {
			var permission record.Permission
			addr := permissionStruct.Addr(&permission)
			err = rows.Scan(addr...)
			if err != nil {
				return errs.Wrap(err, "unable to scan permission")
			}
			permissions = append(permissions, permission)
		}

		if err := rows.Err(); err != nil {
			return errs.Wrap(err, "unable to read query results")
		}

		return nil
	})
	if err != nil {
		return nil, err
	}

	return permissions, nil
}

func (d *Database) DeletePermission(ctx context.Context, tx *sql.Tx, permissionId int64) error {

	clientStruct := sqlbuilder.NewStruct(new(record.Permission)).
		For(d.Flavor)

	deleteBuilder := clientStruct.DeleteFrom("permissions")
	deleteBuilder.Where(deleteBuilder.Equal("id", permissionId))

	sql, args := deleteBuilder.Build()
	_, err := d.ExecSQL(ctx, tx, sql, args...)
	if err != nil {
		return errs.Wrap(err, "unable to delete permission")
	}

	return nil
}
