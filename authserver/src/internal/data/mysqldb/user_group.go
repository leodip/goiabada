package mysqldb

import (
	"database/sql"

	"github.com/leodip/goiabada/internal/entities"
)

func (d *MySQLDatabase) CreateUserGroup(tx *sql.Tx, userGroup *entities.UserGroup) error {
	return d.CommonDB.CreateUserGroup(tx, userGroup)
}

func (d *MySQLDatabase) UpdateUserGroup(tx *sql.Tx, userGroup *entities.UserGroup) error {
	return d.CommonDB.UpdateUserGroup(tx, userGroup)
}

func (d *MySQLDatabase) GetUserGroupById(tx *sql.Tx, userGroupId int64) (*entities.UserGroup, error) {
	return d.CommonDB.GetUserGroupById(tx, userGroupId)
}

func (d *MySQLDatabase) GetUserGroupsByUserIds(tx *sql.Tx, userIds []int64) ([]entities.UserGroup, error) {
	return d.CommonDB.GetUserGroupsByUserIds(tx, userIds)
}

func (d *MySQLDatabase) GetUserGroupsByUserId(tx *sql.Tx, userId int64) ([]entities.UserGroup, error) {
	return d.CommonDB.GetUserGroupsByUserId(tx, userId)
}

func (d *MySQLDatabase) GetUserGroupByUserIdAndGroupId(tx *sql.Tx, userId, groupId int64) (*entities.UserGroup, error) {
	return d.CommonDB.GetUserGroupByUserIdAndGroupId(tx, userId, groupId)
}

func (d *MySQLDatabase) DeleteUserGroup(tx *sql.Tx, userGroupId int64) error {
	return d.CommonDB.DeleteUserGroup(tx, userGroupId)
}
