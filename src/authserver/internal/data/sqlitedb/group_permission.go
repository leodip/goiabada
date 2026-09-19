package sqlitedb

import (
	"database/sql"

	"github.com/leodip/goiabada/authserver/internal/models"
)

func (d *SQLiteDatabase) CreateGroupPermission(tx *sql.Tx, groupPermission *models.GroupPermission) error {
	return d.CommonDB.CreateGroupPermission(tx, groupPermission)
}

func (d *SQLiteDatabase) UpdateGroupPermission(tx *sql.Tx, groupPermission *models.GroupPermission) error {
	return d.CommonDB.UpdateGroupPermission(tx, groupPermission)
}

func (d *SQLiteDatabase) GetGroupPermissionsByGroupId(tx *sql.Tx, groupId int64) ([]models.GroupPermission, error) {
	return d.CommonDB.GetGroupPermissionsByGroupId(tx, groupId)
}

func (d *SQLiteDatabase) GetGroupPermissionsByGroupIds(tx *sql.Tx, groupIds []int64) ([]models.GroupPermission, error) {
	return d.CommonDB.GetGroupPermissionsByGroupIds(tx, groupIds)
}

func (d *SQLiteDatabase) GetGroupPermissionById(tx *sql.Tx, groupPermissionId int64) (*models.GroupPermission, error) {
	return d.CommonDB.GetGroupPermissionById(tx, groupPermissionId)
}

func (d *SQLiteDatabase) GetGroupPermissionByGroupIdAndPermissionId(tx *sql.Tx, groupId, permissionId int64) (*models.GroupPermission, error) {
	return d.CommonDB.GetGroupPermissionByGroupIdAndPermissionId(tx, groupId, permissionId)
}

func (d *SQLiteDatabase) DeleteGroupPermission(tx *sql.Tx, groupPermissionId int64) error {
	return d.CommonDB.DeleteGroupPermission(tx, groupPermissionId)
}
