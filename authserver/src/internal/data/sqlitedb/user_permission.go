package sqlitedb

import (
	"database/sql"

	"github.com/leodip/goiabada/internal/entities"
)

func (d *SQLiteDatabase) CreateUserPermission(tx *sql.Tx, userPermission *entities.UserPermission) error {
	return d.CommonDB.CreateUserPermission(tx, userPermission)
}

func (d *SQLiteDatabase) UpdateUserPermission(tx *sql.Tx, userPermission *entities.UserPermission) error {
	return d.CommonDB.UpdateUserPermission(tx, userPermission)
}

func (d *SQLiteDatabase) GetUserPermissionById(tx *sql.Tx, userPermissionId int64) (*entities.UserPermission, error) {
	return d.CommonDB.GetUserPermissionById(tx, userPermissionId)
}

func (d *SQLiteDatabase) GetUserPermissionsByUserIds(tx *sql.Tx, userIds []int64) ([]entities.UserPermission, error) {
	return d.CommonDB.GetUserPermissionsByUserIds(tx, userIds)
}

func (d *SQLiteDatabase) GetUserPermissionsByUserId(tx *sql.Tx, userId int64) ([]entities.UserPermission, error) {
	return d.CommonDB.GetUserPermissionsByUserId(tx, userId)
}

func (d *SQLiteDatabase) GetUserPermissionByUserIdAndPermissionId(tx *sql.Tx, userId, permissionId int64) (*entities.UserPermission, error) {
	return d.CommonDB.GetUserPermissionByUserIdAndPermissionId(tx, userId, permissionId)
}

func (d *SQLiteDatabase) GetUsersByPermissionIdPaginated(tx *sql.Tx, permissionId int64, page int, pageSize int) ([]entities.User, int, error) {
	return d.CommonDB.GetUsersByPermissionIdPaginated(tx, permissionId, page, pageSize)
}

func (d *SQLiteDatabase) DeleteUserPermission(tx *sql.Tx, userPermissionId int64) error {
	return d.CommonDB.DeleteUserPermission(tx, userPermissionId)
}
