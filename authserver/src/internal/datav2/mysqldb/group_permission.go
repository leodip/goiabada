package mysqldb

import (
	"database/sql"

	"github.com/leodip/goiabada/internal/entitiesv2"
)

func (d *MySQLDatabase) CreateGroupPermission(tx *sql.Tx, groupPermission *entitiesv2.GroupPermission) error {
	return d.CommonDB.CreateGroupPermission(tx, groupPermission)
}

func (d *MySQLDatabase) UpdateGroupPermission(tx *sql.Tx, groupPermission *entitiesv2.GroupPermission) error {
	return d.CommonDB.UpdateGroupPermission(tx, groupPermission)
}

func (d *MySQLDatabase) GetGroupPermissionsByGroupId(tx *sql.Tx, groupId int64) ([]entitiesv2.GroupPermission, error) {
	return d.CommonDB.GetGroupPermissionsByGroupId(tx, groupId)
}

func (d *MySQLDatabase) GetGroupPermissionsByGroupIds(tx *sql.Tx, groupIds []int64) ([]entitiesv2.GroupPermission, error) {
	return d.CommonDB.GetGroupPermissionsByGroupIds(tx, groupIds)
}

func (d *MySQLDatabase) GetGroupPermissionById(tx *sql.Tx, groupPermissionId int64) (*entitiesv2.GroupPermission, error) {
	return d.CommonDB.GetGroupPermissionById(tx, groupPermissionId)
}

func (d *MySQLDatabase) GetGroupPermissionByGroupIdAndPermissionId(tx *sql.Tx, groupId, permissionId int64) (*entitiesv2.GroupPermission, error) {
	return d.CommonDB.GetGroupPermissionByGroupIdAndPermissionId(tx, groupId, permissionId)
}

func (d *MySQLDatabase) DeleteGroupPermission(tx *sql.Tx, groupPermissionId int64) error {
	return d.CommonDB.DeleteGroupPermission(tx, groupPermissionId)
}
