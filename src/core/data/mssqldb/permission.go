package mssqldb

import (
	"database/sql"
	"strings"
	"time"

	"github.com/huandu/go-sqlbuilder"
	"github.com/leodip/goiabada/core/models"
	"github.com/pkg/errors"
)

func (d *MsSQLDatabase) CreatePermission(tx *sql.Tx, permission *models.Permission) error {
	if permission.ResourceId == 0 {
		return errors.WithStack(errors.New("can't create permission with resource_id 0"))
	}

	now := time.Now().UTC()

	originalCreatedAt := permission.CreatedAt
	originalUpdatedAt := permission.UpdatedAt
	permission.CreatedAt = sql.NullTime{Time: now, Valid: true}
	permission.UpdatedAt = sql.NullTime{Time: now, Valid: true}

	permissionStruct := sqlbuilder.NewStruct(new(models.Permission)).
		For(sqlbuilder.SQLServer)

	insertBuilder := permissionStruct.WithoutTag("pk").InsertInto("permissions", permission)
	sql, args := insertBuilder.Build()

	parts := strings.SplitN(sql, "VALUES", 2)
	if len(parts) != 2 {
		return errors.New("unexpected SQL format from sqlbuilder")
	}
	sql = parts[0] + "OUTPUT INSERTED.id VALUES" + parts[1]

	rows, err := d.CommonDB.QuerySql(tx, sql, args...)
	if err != nil {
		permission.CreatedAt = originalCreatedAt
		permission.UpdatedAt = originalUpdatedAt
		return errors.Wrap(err, "unable to insert permission")
	}
	defer func() { _ = rows.Close() }()

	if rows.Next() {
		err = rows.Scan(&permission.Id)
		if err != nil {
			permission.CreatedAt = originalCreatedAt
			permission.UpdatedAt = originalUpdatedAt
			return errors.Wrap(err, "unable to scan permission id")
		}
	}

	return nil
}

func (d *MsSQLDatabase) UpdatePermission(tx *sql.Tx, permission *models.Permission) error {
	return d.CommonDB.UpdatePermission(tx, permission)
}

func (d *MsSQLDatabase) GetPermissionById(tx *sql.Tx, permissionId int64) (*models.Permission, error) {
	return d.CommonDB.GetPermissionById(tx, permissionId)
}

func (d *MsSQLDatabase) GetPermissionsByResourceId(tx *sql.Tx, resourceId int64) ([]models.Permission, error) {
	return d.CommonDB.GetPermissionsByResourceId(tx, resourceId)
}

func (d *MsSQLDatabase) PermissionsLoadResources(tx *sql.Tx, permissions []models.Permission) error {
	return d.CommonDB.PermissionsLoadResources(tx, permissions)
}

func (d *MsSQLDatabase) GetPermissionsByIds(tx *sql.Tx, permissionIds []int64) ([]models.Permission, error) {
	return d.CommonDB.GetPermissionsByIds(tx, permissionIds)
}

func (d *MsSQLDatabase) DeletePermission(tx *sql.Tx, permissionId int64) error {
	return d.CommonDB.DeletePermission(tx, permissionId)
}
