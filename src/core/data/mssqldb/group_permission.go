package mssqldb

import (
	"database/sql"
	"strings"
	"time"

	"github.com/huandu/go-sqlbuilder"
	"github.com/leodip/goiabada/core/models"
	"github.com/pkg/errors"
)

func (d *MsSQLDatabase) CreateGroupPermission(tx *sql.Tx, groupPermission *models.GroupPermission) error {
	if groupPermission.GroupId == 0 {
		return errors.WithStack(errors.New("can't create groupPermission with group_id 0"))
	}

	if groupPermission.PermissionId == 0 {
		return errors.WithStack(errors.New("can't create groupPermission with permission_id 0"))
	}

	now := time.Now().UTC()

	originalCreatedAt := groupPermission.CreatedAt
	originalUpdatedAt := groupPermission.UpdatedAt
	groupPermission.CreatedAt = sql.NullTime{Time: now, Valid: true}
	groupPermission.UpdatedAt = sql.NullTime{Time: now, Valid: true}

	groupPermissionStruct := sqlbuilder.NewStruct(new(models.GroupPermission)).
		For(sqlbuilder.SQLServer)

	insertBuilder := groupPermissionStruct.WithoutTag("pk").InsertInto("groups_permissions", groupPermission)
	sql, args := insertBuilder.Build()

	parts := strings.SplitN(sql, "VALUES", 2)
	if len(parts) != 2 {
		return errors.New("unexpected SQL format from sqlbuilder")
	}
	sql = parts[0] + "OUTPUT INSERTED.id VALUES" + parts[1]

	rows, err := d.CommonDB.QuerySql(tx, sql, args...)
	if err != nil {
		groupPermission.CreatedAt = originalCreatedAt
		groupPermission.UpdatedAt = originalUpdatedAt
		return errors.Wrap(err, "unable to insert groupPermission")
	}
	defer rows.Close()

	if rows.Next() {
		err = rows.Scan(&groupPermission.Id)
		if err != nil {
			groupPermission.CreatedAt = originalCreatedAt
			groupPermission.UpdatedAt = originalUpdatedAt
			return errors.Wrap(err, "unable to scan groupPermission id")
		}
	}

	return nil
}

func (d *MsSQLDatabase) UpdateGroupPermission(tx *sql.Tx, groupPermission *models.GroupPermission) error {
	return d.CommonDB.UpdateGroupPermission(tx, groupPermission)
}

func (d *MsSQLDatabase) GetGroupPermissionsByGroupId(tx *sql.Tx, groupId int64) ([]models.GroupPermission, error) {
	return d.CommonDB.GetGroupPermissionsByGroupId(tx, groupId)
}

func (d *MsSQLDatabase) GetGroupPermissionsByGroupIds(tx *sql.Tx, groupIds []int64) ([]models.GroupPermission, error) {
	return d.CommonDB.GetGroupPermissionsByGroupIds(tx, groupIds)
}

func (d *MsSQLDatabase) GetGroupPermissionById(tx *sql.Tx, groupPermissionId int64) (*models.GroupPermission, error) {
	return d.CommonDB.GetGroupPermissionById(tx, groupPermissionId)
}

func (d *MsSQLDatabase) GetGroupPermissionByGroupIdAndPermissionId(tx *sql.Tx, groupId, permissionId int64) (*models.GroupPermission, error) {
	return d.CommonDB.GetGroupPermissionByGroupIdAndPermissionId(tx, groupId, permissionId)
}

func (d *MsSQLDatabase) DeleteGroupPermission(tx *sql.Tx, groupPermissionId int64) error {
	return d.CommonDB.DeleteGroupPermission(tx, groupPermissionId)
}
