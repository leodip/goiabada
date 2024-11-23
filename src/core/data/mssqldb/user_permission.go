package mssqldb

import (
	"database/sql"
	"strings"
	"time"

	"github.com/huandu/go-sqlbuilder"
	"github.com/leodip/goiabada/core/models"
	"github.com/pkg/errors"
)

func (d *MsSQLDatabase) CreateUserPermission(tx *sql.Tx, userPermission *models.UserPermission) error {
	if userPermission.UserId == 0 {
		return errors.WithStack(errors.New("can't create userPermission with user_id 0"))
	}

	if userPermission.PermissionId == 0 {
		return errors.WithStack(errors.New("can't create userPermission with permission_id 0"))
	}

	now := time.Now().UTC()

	originalCreatedAt := userPermission.CreatedAt
	originalUpdatedAt := userPermission.UpdatedAt
	userPermission.CreatedAt = sql.NullTime{Time: now, Valid: true}
	userPermission.UpdatedAt = sql.NullTime{Time: now, Valid: true}

	userPermissionStruct := sqlbuilder.NewStruct(new(models.UserPermission)).
		For(sqlbuilder.SQLServer)

	insertBuilder := userPermissionStruct.WithoutTag("pk").InsertInto("users_permissions", userPermission)
	sql, args := insertBuilder.Build()

	parts := strings.SplitN(sql, "VALUES", 2)
	if len(parts) != 2 {
		return errors.New("unexpected SQL format from sqlbuilder")
	}
	sql = parts[0] + "OUTPUT INSERTED.id VALUES" + parts[1]

	rows, err := d.CommonDB.QuerySql(tx, sql, args...)
	if err != nil {
		userPermission.CreatedAt = originalCreatedAt
		userPermission.UpdatedAt = originalUpdatedAt
		return errors.Wrap(err, "unable to insert userPermission")
	}
	defer rows.Close()

	if rows.Next() {
		err = rows.Scan(&userPermission.Id)
		if err != nil {
			userPermission.CreatedAt = originalCreatedAt
			userPermission.UpdatedAt = originalUpdatedAt
			return errors.Wrap(err, "unable to scan userPermission id")
		}
	}

	return nil
}

func (d *MsSQLDatabase) UpdateUserPermission(tx *sql.Tx, userPermission *models.UserPermission) error {
	return d.CommonDB.UpdateUserPermission(tx, userPermission)
}

func (d *MsSQLDatabase) GetUserPermissionById(tx *sql.Tx, userPermissionId int64) (*models.UserPermission, error) {
	return d.CommonDB.GetUserPermissionById(tx, userPermissionId)
}

func (d *MsSQLDatabase) GetUserPermissionsByUserIds(tx *sql.Tx, userIds []int64) ([]models.UserPermission, error) {
	return d.CommonDB.GetUserPermissionsByUserIds(tx, userIds)
}

func (d *MsSQLDatabase) GetUserPermissionsByUserId(tx *sql.Tx, userId int64) ([]models.UserPermission, error) {
	return d.CommonDB.GetUserPermissionsByUserId(tx, userId)
}

func (d *MsSQLDatabase) GetUserPermissionByUserIdAndPermissionId(tx *sql.Tx, userId, permissionId int64) (*models.UserPermission, error) {
	return d.CommonDB.GetUserPermissionByUserIdAndPermissionId(tx, userId, permissionId)
}

func (d *MsSQLDatabase) GetUsersByPermissionIdPaginated(tx *sql.Tx, permissionId int64, page int, pageSize int) ([]models.User, int, error) {
	return d.CommonDB.GetUsersByPermissionIdPaginated(tx, permissionId, page, pageSize)
}

func (d *MsSQLDatabase) DeleteUserPermission(tx *sql.Tx, userPermissionId int64) error {
	return d.CommonDB.DeleteUserPermission(tx, userPermissionId)
}
