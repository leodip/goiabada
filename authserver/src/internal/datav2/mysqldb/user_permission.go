package mysqldb

import (
	"database/sql"

	"github.com/leodip/goiabada/internal/entitiesv2"
)

func (d *MySQLDatabase) CreateUserPermission(tx *sql.Tx, userPermission *entitiesv2.UserPermission) error {
	return d.CommonDB.CreateUserPermission(tx, userPermission)
}

func (d *MySQLDatabase) UpdateUserPermission(tx *sql.Tx, userPermission *entitiesv2.UserPermission) error {
	return d.CommonDB.UpdateUserPermission(tx, userPermission)
}

func (d *MySQLDatabase) GetUserPermissionById(tx *sql.Tx, userPermissionId int64) (*entitiesv2.UserPermission, error) {
	return d.CommonDB.GetUserPermissionById(tx, userPermissionId)
}

func (d *MySQLDatabase) GetUserPermissionsByUserIds(tx *sql.Tx, userIds []int64) ([]entitiesv2.UserPermission, error) {
	return d.CommonDB.GetUserPermissionsByUserIds(tx, userIds)
}

func (d *MySQLDatabase) GetUserPermissionsByUserId(tx *sql.Tx, userId int64) ([]entitiesv2.UserPermission, error) {
	return d.CommonDB.GetUserPermissionsByUserId(tx, userId)
}

func (d *MySQLDatabase) GetUserPermissionByUserIdAndPermissionId(tx *sql.Tx, userId, permissionId int64) (*entitiesv2.UserPermission, error) {
	return d.CommonDB.GetUserPermissionByUserIdAndPermissionId(tx, userId, permissionId)
}

func (d *MySQLDatabase) GetUsersByPermissionIdPaginated(tx *sql.Tx, permissionId int64, page int, pageSize int) ([]entitiesv2.User, int, error) {
	return d.CommonDB.GetUsersByPermissionIdPaginated(tx, permissionId, page, pageSize)
}

func (d *MySQLDatabase) DeleteUserPermission(tx *sql.Tx, userPermissionId int64) error {
	return d.CommonDB.DeleteUserPermission(tx, userPermissionId)
}
