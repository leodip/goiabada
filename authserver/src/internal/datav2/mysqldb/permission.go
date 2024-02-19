package mysqldb

import (
	"database/sql"

	"github.com/leodip/goiabada/internal/entitiesv2"
)

func (d *MySQLDatabase) CreatePermission(tx *sql.Tx, permission *entitiesv2.Permission) error {
	return d.CommonDB.CreatePermission(tx, permission)
}

func (d *MySQLDatabase) UpdatePermission(tx *sql.Tx, permission *entitiesv2.Permission) error {
	return d.CommonDB.UpdatePermission(tx, permission)
}

func (d *MySQLDatabase) GetPermissionById(tx *sql.Tx, permissionId int64) (*entitiesv2.Permission, error) {
	return d.CommonDB.GetPermissionById(tx, permissionId)
}

func (d *MySQLDatabase) GetPermissionByPermissionIdentifier(tx *sql.Tx, permissionIdentifier string) (*entitiesv2.Permission, error) {
	return d.CommonDB.GetPermissionByPermissionIdentifier(tx, permissionIdentifier)
}

func (d *MySQLDatabase) GetPermissionsByResourceId(tx *sql.Tx, resourceId int64) ([]entitiesv2.Permission, error) {
	return d.CommonDB.GetPermissionsByResourceId(tx, resourceId)
}

func (d *MySQLDatabase) PermissionsLoadResources(tx *sql.Tx, permissions []entitiesv2.Permission) error {
	return d.CommonDB.PermissionsLoadResources(tx, permissions)
}

func (d *MySQLDatabase) GetPermissionsByIds(tx *sql.Tx, permissionIds []int64) ([]entitiesv2.Permission, error) {
	return d.CommonDB.GetPermissionsByIds(tx, permissionIds)
}

func (d *MySQLDatabase) DeletePermission(tx *sql.Tx, permissionId int64) error {
	return d.CommonDB.DeletePermission(tx, permissionId)
}
