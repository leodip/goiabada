package commondb

import (
	"database/sql"
	"time"

	"github.com/huandu/go-sqlbuilder"
	"github.com/leodip/goiabada/internal/entitiesv2"
	"github.com/pkg/errors"
)

func SetUsersPermissionsInsertColsAndValues(insertBuilder *sqlbuilder.InsertBuilder, usersPermissions *entitiesv2.UserPermission) *sqlbuilder.InsertBuilder {
	insertBuilder.InsertInto("users_permissions")
	insertBuilder.Cols(
		"created_at",
		"updated_at",
		"user_id",
		"permission_id",
	)
	now := time.Now().UTC()
	insertBuilder.Values(
		now,
		now,
		usersPermissions.UserId,
		usersPermissions.PermissionId,
	)

	return insertBuilder
}

func ScanUsersPermissions(rows *sql.Rows) (*entitiesv2.UserPermission, error) {
	var (
		id            int64
		created_at    time.Time
		updated_at    time.Time
		user_id       int64
		permission_id int64
	)

	err := rows.Scan(
		&id,
		&created_at,
		&updated_at,
		&user_id,
		&permission_id,
	)
	if err != nil {
		return nil, errors.Wrap(err, "unable to scan users permissions")
	}

	usersPermissions := &entitiesv2.UserPermission{
		Id:           id,
		CreatedAt:    created_at,
		UpdatedAt:    updated_at,
		UserId:       user_id,
		PermissionId: permission_id,
	}

	return usersPermissions, nil
}
