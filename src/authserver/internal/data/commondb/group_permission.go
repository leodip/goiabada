package commondb

import (
	"context"
	"database/sql"
	"time"

	"github.com/huandu/go-sqlbuilder"
	"github.com/leodip/goiabada/authserver/internal/models"
	"github.com/leodip/goiabada/core/errs"
)

func (d *CommonDatabase) CreateGroupPermission(ctx context.Context, tx *sql.Tx, groupPermission *models.GroupPermission) error {

	if groupPermission.GroupId == 0 {
		return errs.New("can't create groupPermission with group_id 0")
	}

	if groupPermission.PermissionId == 0 {
		return errs.New("can't create groupPermission with permission_id 0")
	}

	now := time.Now().UTC()

	originalCreatedAt := groupPermission.CreatedAt
	originalUpdatedAt := groupPermission.UpdatedAt
	groupPermission.CreatedAt = sql.NullTime{Time: now, Valid: true}
	groupPermission.UpdatedAt = sql.NullTime{Time: now, Valid: true}

	groupPermissionStruct := sqlbuilder.NewStruct(new(models.GroupPermission)).
		For(d.Flavor)

	insertBuilder := groupPermissionStruct.WithoutTag("pk").InsertInto("groups_permissions", groupPermission)

	id, err := d.insertReturningId(ctx, tx, insertBuilder, "groupPermission")
	if err != nil {
		groupPermission.CreatedAt = originalCreatedAt
		groupPermission.UpdatedAt = originalUpdatedAt
		return err
	}

	groupPermission.Id = id
	return nil
}

func (d *CommonDatabase) UpdateGroupPermission(ctx context.Context, tx *sql.Tx, groupPermission *models.GroupPermission) error {

	if groupPermission.Id == 0 {
		return errs.New("can't update groupPermission with id 0")
	}

	originalUpdatedAt := groupPermission.UpdatedAt
	groupPermission.UpdatedAt = sql.NullTime{Time: time.Now().UTC(), Valid: true}

	groupPermissionStruct := sqlbuilder.NewStruct(new(models.GroupPermission)).
		For(d.Flavor)

	updateBuilder := groupPermissionStruct.WithoutTag("pk").WithoutTag("dont-update").Update("groups_permissions", groupPermission)
	updateBuilder.Where(updateBuilder.Equal("id", groupPermission.Id))

	sql, args := updateBuilder.Build()
	_, err := d.ExecSql(ctx, tx, sql, args...)
	if err != nil {
		groupPermission.UpdatedAt = originalUpdatedAt
		return errs.Wrap(err, "unable to update groupPermission")
	}

	return nil
}

func (d *CommonDatabase) getGroupPermissionCommon(ctx context.Context, tx *sql.Tx, selectBuilder *sqlbuilder.SelectBuilder,
	groupPermissionStruct *sqlbuilder.Struct) (*models.GroupPermission, error) {

	sql, args := selectBuilder.Build()
	rows, err := d.QuerySql(ctx, tx, sql, args...)
	if err != nil {
		return nil, errs.Wrap(err, "unable to query database")
	}
	defer func() { _ = rows.Close() }()

	var groupPermission models.GroupPermission
	if rows.Next() {
		addr := groupPermissionStruct.Addr(&groupPermission)
		err = rows.Scan(addr...)
		if err != nil {
			return nil, errs.Wrap(err, "unable to scan groupPermission")
		}
		return &groupPermission, nil
	}
	if err := rows.Err(); err != nil {
		return nil, errs.Wrap(err, "unable to read query results")
	}

	return nil, nil
}

func (d *CommonDatabase) GetGroupPermissionsByGroupId(ctx context.Context, tx *sql.Tx, groupId int64) ([]models.GroupPermission, error) {

	groupPermissionStruct := sqlbuilder.NewStruct(new(models.GroupPermission)).
		For(d.Flavor)

	selectBuilder := groupPermissionStruct.SelectFrom("groups_permissions")
	selectBuilder.Where(selectBuilder.Equal("group_id", groupId))

	sql, args := selectBuilder.Build()
	rows, err := d.QuerySql(ctx, tx, sql, args...)
	if err != nil {
		return nil, errs.Wrap(err, "unable to query database")
	}
	defer func() { _ = rows.Close() }()

	var groupPermissions []models.GroupPermission
	for rows.Next() {
		var groupPermission models.GroupPermission
		addr := groupPermissionStruct.Addr(&groupPermission)
		err = rows.Scan(addr...)
		if err != nil {
			return nil, errs.Wrap(err, "unable to scan groupPermission")
		}
		groupPermissions = append(groupPermissions, groupPermission)
	}

	if err := rows.Err(); err != nil {
		return nil, errs.Wrap(err, "unable to read query results")
	}

	return groupPermissions, nil
}

func (d *CommonDatabase) GetGroupPermissionsByGroupIds(ctx context.Context, tx *sql.Tx, groupIds []int64) ([]models.GroupPermission, error) {

	if len(groupIds) == 0 {
		return nil, nil
	}

	var groupPermissions []models.GroupPermission

	err := forEachIdBatch(groupIds, func(batch []int64) error {
		groupPermissionStruct := sqlbuilder.NewStruct(new(models.GroupPermission)).
			For(d.Flavor)

		selectBuilder := groupPermissionStruct.SelectFrom("groups_permissions")
		selectBuilder.Where(selectBuilder.In("group_id", sqlbuilder.Flatten(batch)...))

		sql, args := selectBuilder.Build()
		rows, err := d.QuerySql(ctx, tx, sql, args...)
		if err != nil {
			return errs.Wrap(err, "unable to query database")
		}
		defer func() { _ = rows.Close() }()

		for rows.Next() {
			var groupPermission models.GroupPermission
			addr := groupPermissionStruct.Addr(&groupPermission)
			err = rows.Scan(addr...)
			if err != nil {
				return errs.Wrap(err, "unable to scan groupPermission")
			}
			groupPermissions = append(groupPermissions, groupPermission)
		}

		if err := rows.Err(); err != nil {
			return errs.Wrap(err, "unable to read query results")
		}

		return nil
	})
	if err != nil {
		return nil, err
	}

	return groupPermissions, nil
}

func (d *CommonDatabase) GetGroupPermissionById(ctx context.Context, tx *sql.Tx, groupPermissionId int64) (*models.GroupPermission, error) {

	groupPermissionStruct := sqlbuilder.NewStruct(new(models.GroupPermission)).
		For(d.Flavor)

	selectBuilder := groupPermissionStruct.SelectFrom("groups_permissions")
	selectBuilder.Where(selectBuilder.Equal("id", groupPermissionId))

	groupPermission, err := d.getGroupPermissionCommon(ctx, tx, selectBuilder, groupPermissionStruct)
	if err != nil {
		return nil, err
	}

	return groupPermission, nil
}

func (d *CommonDatabase) GetGroupPermissionByGroupIdAndPermissionId(ctx context.Context, tx *sql.Tx, groupId, permissionId int64) (*models.GroupPermission, error) {

	groupPermissionStruct := sqlbuilder.NewStruct(new(models.GroupPermission)).
		For(d.Flavor)

	selectBuilder := groupPermissionStruct.SelectFrom("groups_permissions")
	selectBuilder.Where(selectBuilder.Equal("group_id", groupId))
	selectBuilder.Where(selectBuilder.Equal("permission_id", permissionId))

	groupPermission, err := d.getGroupPermissionCommon(ctx, tx, selectBuilder, groupPermissionStruct)
	if err != nil {
		return nil, err
	}

	return groupPermission, nil
}

func (d *CommonDatabase) DeleteGroupPermission(ctx context.Context, tx *sql.Tx, groupPermissionId int64) error {

	groupStruct := sqlbuilder.NewStruct(new(models.GroupPermission)).
		For(d.Flavor)

	deleteBuilder := groupStruct.DeleteFrom("groups_permissions")
	deleteBuilder.Where(deleteBuilder.Equal("id", groupPermissionId))

	sql, args := deleteBuilder.Build()
	_, err := d.ExecSql(ctx, tx, sql, args...)
	if err != nil {
		return errs.Wrap(err, "unable to delete groupPermission")
	}

	return nil
}
