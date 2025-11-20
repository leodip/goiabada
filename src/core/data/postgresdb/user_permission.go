package postgresdb

import (
	"database/sql"
	"time"

	"github.com/huandu/go-sqlbuilder"
	"github.com/leodip/goiabada/core/models"
	"github.com/pkg/errors"
)

func (d *PostgresDatabase) CreateUserPermission(tx *sql.Tx, userPermission *models.UserPermission) error {
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
		For(sqlbuilder.PostgreSQL)

	insertBuilder := userPermissionStruct.WithoutTag("pk").InsertInto("users_permissions", userPermission)

	sql, args := insertBuilder.Build()
	sql = sql + " RETURNING id"

	rows, err := d.CommonDB.QuerySql(tx, sql, args...)
	if err != nil {
		userPermission.CreatedAt = originalCreatedAt
		userPermission.UpdatedAt = originalUpdatedAt
		return errors.Wrap(err, "unable to insert userPermission")
	}
	defer func() { _ = rows.Close() }()

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

func (d *PostgresDatabase) UpdateUserPermission(tx *sql.Tx, userPermission *models.UserPermission) error {
	return d.CommonDB.UpdateUserPermission(tx, userPermission)
}

func (d *PostgresDatabase) GetUserPermissionById(tx *sql.Tx, userPermissionId int64) (*models.UserPermission, error) {
	return d.CommonDB.GetUserPermissionById(tx, userPermissionId)
}

func (d *PostgresDatabase) GetUserPermissionsByUserIds(tx *sql.Tx, userIds []int64) ([]models.UserPermission, error) {
	return d.CommonDB.GetUserPermissionsByUserIds(tx, userIds)
}

func (d *PostgresDatabase) GetUserPermissionsByUserId(tx *sql.Tx, userId int64) ([]models.UserPermission, error) {
	return d.CommonDB.GetUserPermissionsByUserId(tx, userId)
}

func (d *PostgresDatabase) GetUserPermissionByUserIdAndPermissionId(tx *sql.Tx, userId, permissionId int64) (*models.UserPermission, error) {
	return d.CommonDB.GetUserPermissionByUserIdAndPermissionId(tx, userId, permissionId)
}

func (d *PostgresDatabase) GetUsersByPermissionIdPaginated(tx *sql.Tx, permissionId int64, page int, pageSize int) ([]models.User, int, error) {
	return d.CommonDB.GetUsersByPermissionIdPaginated(tx, permissionId, page, pageSize)
}

func (d *PostgresDatabase) DeleteUserPermission(tx *sql.Tx, userPermissionId int64) error {
	return d.CommonDB.DeleteUserPermission(tx, userPermissionId)
}
