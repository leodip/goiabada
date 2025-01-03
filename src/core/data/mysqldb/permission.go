package mysqldb

import (
	"database/sql"

	"github.com/leodip/goiabada/core/models"
)

func (d *MySQLDatabase) CreatePermission(tx *sql.Tx, permission *models.Permission) error {
	return d.CommonDB.CreatePermission(tx, permission)
}

func (d *MySQLDatabase) UpdatePermission(tx *sql.Tx, permission *models.Permission) error {
	return d.CommonDB.UpdatePermission(tx, permission)
}

func (d *MySQLDatabase) GetPermissionById(tx *sql.Tx, permissionId int64) (*models.Permission, error) {
	return d.CommonDB.GetPermissionById(tx, permissionId)
}

func (d *MySQLDatabase) GetPermissionsByResourceId(tx *sql.Tx, resourceId int64) ([]models.Permission, error) {
	return d.CommonDB.GetPermissionsByResourceId(tx, resourceId)
}

func (d *MySQLDatabase) PermissionsLoadResources(tx *sql.Tx, permissions []models.Permission) error {
	return d.CommonDB.PermissionsLoadResources(tx, permissions)
}

func (d *MySQLDatabase) GetPermissionsByIds(tx *sql.Tx, permissionIds []int64) ([]models.Permission, error) {
	return d.CommonDB.GetPermissionsByIds(tx, permissionIds)
}

func (d *MySQLDatabase) DeletePermission(tx *sql.Tx, permissionId int64) error {
	return d.CommonDB.DeletePermission(tx, permissionId)
}
