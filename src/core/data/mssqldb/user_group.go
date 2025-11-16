package mssqldb

import (
	"database/sql"
	"strings"
	"time"

	"github.com/huandu/go-sqlbuilder"
	"github.com/leodip/goiabada/core/models"
	"github.com/pkg/errors"
)

func (d *MsSQLDatabase) CreateUserGroup(tx *sql.Tx, userGroup *models.UserGroup) error {
	if userGroup.UserId == 0 {
		return errors.WithStack(errors.New("can't create userGroup with user_id 0"))
	}

	if userGroup.GroupId == 0 {
		return errors.WithStack(errors.New("can't create userGroup with group_id 0"))
	}

	now := time.Now().UTC()

	originalCreatedAt := userGroup.CreatedAt
	originalUpdatedAt := userGroup.UpdatedAt
	userGroup.CreatedAt = sql.NullTime{Time: now, Valid: true}
	userGroup.UpdatedAt = sql.NullTime{Time: now, Valid: true}

	userGroupStruct := sqlbuilder.NewStruct(new(models.UserGroup)).
		For(sqlbuilder.SQLServer)

	insertBuilder := userGroupStruct.WithoutTag("pk").InsertInto("users_groups", userGroup)
	sql, args := insertBuilder.Build()

	parts := strings.SplitN(sql, "VALUES", 2)
	if len(parts) != 2 {
		return errors.New("unexpected SQL format from sqlbuilder")
	}
	sql = parts[0] + "OUTPUT INSERTED.id VALUES" + parts[1]

	rows, err := d.CommonDB.QuerySql(tx, sql, args...)
	if err != nil {
		userGroup.CreatedAt = originalCreatedAt
		userGroup.UpdatedAt = originalUpdatedAt
		return errors.Wrap(err, "unable to insert userGroup")
	}
	defer func() { _ = rows.Close() }()

	if rows.Next() {
		err = rows.Scan(&userGroup.Id)
		if err != nil {
			userGroup.CreatedAt = originalCreatedAt
			userGroup.UpdatedAt = originalUpdatedAt
			return errors.Wrap(err, "unable to scan userGroup id")
		}
	}

	return nil
}

func (d *MsSQLDatabase) UpdateUserGroup(tx *sql.Tx, userGroup *models.UserGroup) error {
	return d.CommonDB.UpdateUserGroup(tx, userGroup)
}

func (d *MsSQLDatabase) GetUserGroupById(tx *sql.Tx, userGroupId int64) (*models.UserGroup, error) {
	return d.CommonDB.GetUserGroupById(tx, userGroupId)
}

func (d *MsSQLDatabase) GetUserGroupsByUserIds(tx *sql.Tx, userIds []int64) ([]models.UserGroup, error) {
	return d.CommonDB.GetUserGroupsByUserIds(tx, userIds)
}

func (d *MsSQLDatabase) GetUserGroupsByUserId(tx *sql.Tx, userId int64) ([]models.UserGroup, error) {
	return d.CommonDB.GetUserGroupsByUserId(tx, userId)
}

func (d *MsSQLDatabase) GetUserGroupByUserIdAndGroupId(tx *sql.Tx, userId, groupId int64) (*models.UserGroup, error) {
	return d.CommonDB.GetUserGroupByUserIdAndGroupId(tx, userId, groupId)
}

func (d *MsSQLDatabase) DeleteUserGroup(tx *sql.Tx, userGroupId int64) error {
	return d.CommonDB.DeleteUserGroup(tx, userGroupId)
}
