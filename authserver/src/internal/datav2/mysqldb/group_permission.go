package mysqldb

import (
	"database/sql"
	"time"

	"github.com/huandu/go-sqlbuilder"
	"github.com/leodip/goiabada/internal/entitiesv2"
	"github.com/pkg/errors"
)

func (d *MySQLDatabase) CreateGroupPermission(tx *sql.Tx, groupPermission *entitiesv2.GroupPermission) error {

	if groupPermission.GroupId == 0 {
		return errors.New("can't create groupPermission with group_id 0")
	}

	if groupPermission.PermissionId == 0 {
		return errors.New("can't create groupPermission with permission_id 0")
	}

	now := time.Now().UTC()

	originalCreatedAt := groupPermission.CreatedAt
	originalUpdatedAt := groupPermission.UpdatedAt
	groupPermission.CreatedAt = sql.NullTime{Time: now, Valid: true}
	groupPermission.UpdatedAt = sql.NullTime{Time: now, Valid: true}

	groupPermissionStruct := sqlbuilder.NewStruct(new(entitiesv2.GroupPermission)).
		For(sqlbuilder.MySQL)

	insertBuilder := groupPermissionStruct.WithoutTag("pk").InsertInto("groups_permissions", groupPermission)

	sql, args := insertBuilder.Build()
	result, err := d.execSql(tx, sql, args...)
	if err != nil {
		groupPermission.CreatedAt = originalCreatedAt
		groupPermission.UpdatedAt = originalUpdatedAt
		return errors.Wrap(err, "unable to insert groupPermission")
	}

	id, err := result.LastInsertId()
	if err != nil {
		groupPermission.CreatedAt = originalCreatedAt
		groupPermission.UpdatedAt = originalUpdatedAt
		return errors.Wrap(err, "unable to get last insert id")
	}

	groupPermission.Id = id
	return nil
}

func (d *MySQLDatabase) UpdateGroupPermission(tx *sql.Tx, groupPermission *entitiesv2.GroupPermission) error {

	if groupPermission.Id == 0 {
		return errors.New("can't update groupPermission with id 0")
	}

	originalUpdatedAt := groupPermission.UpdatedAt
	groupPermission.UpdatedAt = sql.NullTime{Time: time.Now().UTC(), Valid: true}

	groupPermissionStruct := sqlbuilder.NewStruct(new(entitiesv2.GroupPermission)).
		For(sqlbuilder.MySQL)

	updateBuilder := groupPermissionStruct.WithoutTag("pk").Update("groups_permissions", groupPermission)
	updateBuilder.Where(updateBuilder.Equal("id", groupPermission.Id))

	sql, args := updateBuilder.Build()
	_, err := d.execSql(tx, sql, args...)
	if err != nil {
		groupPermission.UpdatedAt = originalUpdatedAt
		return errors.Wrap(err, "unable to update groupPermission")
	}

	return nil
}

func (d *MySQLDatabase) getGroupPermissionCommon(tx *sql.Tx, selectBuilder *sqlbuilder.SelectBuilder,
	groupPermissionStruct *sqlbuilder.Struct) (*entitiesv2.GroupPermission, error) {

	sql, args := selectBuilder.Build()
	rows, err := d.querySql(tx, sql, args...)
	if err != nil {
		return nil, errors.Wrap(err, "unable to query database")
	}
	defer rows.Close()

	var groupPermission entitiesv2.GroupPermission
	if rows.Next() {
		addr := groupPermissionStruct.Addr(&groupPermission)
		err = rows.Scan(addr...)
		if err != nil {
			return nil, errors.Wrap(err, "unable to scan groupPermission")
		}
		return &groupPermission, nil
	}
	return nil, nil
}

func (d *MySQLDatabase) GetGroupPermissionById(tx *sql.Tx, groupPermissionId int64) (*entitiesv2.GroupPermission, error) {

	if groupPermissionId <= 0 {
		return nil, errors.New("groupPermission id must be greater than 0")
	}

	groupPermissionStruct := sqlbuilder.NewStruct(new(entitiesv2.GroupPermission)).
		For(sqlbuilder.MySQL)

	selectBuilder := groupPermissionStruct.SelectFrom("groups_permissions")
	selectBuilder.Where(selectBuilder.Equal("id", groupPermissionId))

	groupPermission, err := d.getGroupPermissionCommon(tx, selectBuilder, groupPermissionStruct)
	if err != nil {
		return nil, err
	}

	return groupPermission, nil
}

func (d *MySQLDatabase) DeleteGroupPermission(tx *sql.Tx, groupPermissionId int64) error {
	if groupPermissionId <= 0 {
		return errors.New("groupPermissionId must be greater than 0")
	}

	groupStruct := sqlbuilder.NewStruct(new(entitiesv2.GroupPermission)).
		For(sqlbuilder.MySQL)

	deleteBuilder := groupStruct.DeleteFrom("groups_permissions")
	deleteBuilder.Where(deleteBuilder.Equal("id", groupPermissionId))

	sql, args := deleteBuilder.Build()
	_, err := d.execSql(tx, sql, args...)
	if err != nil {
		return errors.Wrap(err, "unable to delete groupPermission")
	}

	return nil
}
