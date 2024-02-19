package sqlitedb

import (
	"database/sql"

	"github.com/leodip/goiabada/internal/entitiesv2"
)

func (d *SQLiteDatabase) CreatePermission(tx *sql.Tx, permission *entitiesv2.Permission) error {
	return d.CommonDB.CreatePermission(tx, permission)
}

func (d *SQLiteDatabase) UpdatePermission(tx *sql.Tx, permission *entitiesv2.Permission) error {
	return d.CommonDB.UpdatePermission(tx, permission)
}

func (d *SQLiteDatabase) GetPermissionById(tx *sql.Tx, permissionId int64) (*entitiesv2.Permission, error) {
	return d.CommonDB.GetPermissionById(tx, permissionId)
}

func (d *SQLiteDatabase) GetPermissionByPermissionIdentifier(tx *sql.Tx, permissionIdentifier string) (*entitiesv2.Permission, error) {
	return d.CommonDB.GetPermissionByPermissionIdentifier(tx, permissionIdentifier)
}

func (d *SQLiteDatabase) GetPermissionsByResourceId(tx *sql.Tx, resourceId int64) ([]entitiesv2.Permission, error) {
	return d.CommonDB.GetPermissionsByResourceId(tx, resourceId)
}

func (d *SQLiteDatabase) PermissionsLoadResources(tx *sql.Tx, permissions []entitiesv2.Permission) error {
	return d.CommonDB.PermissionsLoadResources(tx, permissions)
}

func (d *SQLiteDatabase) GetPermissionsByIds(tx *sql.Tx, permissionIds []int64) ([]entitiesv2.Permission, error) {
	return d.CommonDB.GetPermissionsByIds(tx, permissionIds)
}

func (d *SQLiteDatabase) DeletePermission(tx *sql.Tx, permissionId int64) error {
	return d.CommonDB.DeletePermission(tx, permissionId)
}
