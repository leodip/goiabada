package mssqldb

import (
	"database/sql"
	"strings"
	"time"

	"github.com/huandu/go-sqlbuilder"
	"github.com/leodip/goiabada/authserver/internal/models"
	"github.com/leodip/goiabada/core/errs"
)

func (d *MsSQLDatabase) CreateUserPermission(tx *sql.Tx, userPermission *models.UserPermission) error {
	if userPermission.UserId == 0 {
		return errs.New("can't create userPermission with user_id 0")
	}

	if userPermission.PermissionId == 0 {
		return errs.New("can't create userPermission with permission_id 0")
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
		return errs.New("unexpected SQL format from sqlbuilder")
	}
	sql = parts[0] + "OUTPUT INSERTED.id VALUES" + parts[1]

	rows, err := d.QuerySql(tx, sql, args...)
	if err != nil {
		userPermission.CreatedAt = originalCreatedAt
		userPermission.UpdatedAt = originalUpdatedAt
		return errs.Wrap(err, "unable to insert userPermission")
	}
	defer func() { _ = rows.Close() }()

	if rows.Next() {
		err = rows.Scan(&userPermission.Id)
		if err != nil {
			userPermission.CreatedAt = originalCreatedAt
			userPermission.UpdatedAt = originalUpdatedAt
			return errs.Wrap(err, "unable to scan userPermission id")
		}
	}

	// The driver can defer a constraint violation to the result set rather than
	// returning it from the query, in which case Next() simply reports no row.
	// Without this the insert would look like a success with id 0.
	if err := rows.Err(); err != nil {
		userPermission.CreatedAt = originalCreatedAt
		userPermission.UpdatedAt = originalUpdatedAt
		return d.WrapSQLError(err, "unable to insert userPermission")
	}

	return nil
}
