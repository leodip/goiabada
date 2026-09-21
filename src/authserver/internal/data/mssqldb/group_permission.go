package mssqldb

import (
	"database/sql"
	"strings"
	"time"

	"github.com/huandu/go-sqlbuilder"
	"github.com/leodip/goiabada/authserver/internal/models"
	"github.com/leodip/goiabada/core/errs"
)

func (d *MsSQLDatabase) CreateGroupPermission(tx *sql.Tx, groupPermission *models.GroupPermission) error {
	if groupPermission.GroupId == 0 {
		return errs.New("can't create groupPermission with group_id 0")
	}

	if groupPermission.PermissionId == 0 {
		return errs.New("can't create groupPermission with permission_id 0")
	}

	now := time.Now().UTC()

	originalCreatedAt := groupPermission.CreatedAt
	originalUpdatedAt := groupPermission.UpdatedAt
	groupPermission.CreatedAt = sql.NullTime{Time: now, Valid: true}
	groupPermission.UpdatedAt = sql.NullTime{Time: now, Valid: true}

	groupPermissionStruct := sqlbuilder.NewStruct(new(models.GroupPermission)).
		For(sqlbuilder.SQLServer)

	insertBuilder := groupPermissionStruct.WithoutTag("pk").InsertInto("groups_permissions", groupPermission)
	sql, args := insertBuilder.Build()

	parts := strings.SplitN(sql, "VALUES", 2)
	if len(parts) != 2 {
		return errs.New("unexpected SQL format from sqlbuilder")
	}
	sql = parts[0] + "OUTPUT INSERTED.id VALUES" + parts[1]

	rows, err := d.QuerySql(tx, sql, args...)
	if err != nil {
		groupPermission.CreatedAt = originalCreatedAt
		groupPermission.UpdatedAt = originalUpdatedAt
		return errs.Wrap(err, "unable to insert groupPermission")
	}
	defer func() { _ = rows.Close() }()

	if rows.Next() {
		err = rows.Scan(&groupPermission.Id)
		if err != nil {
			groupPermission.CreatedAt = originalCreatedAt
			groupPermission.UpdatedAt = originalUpdatedAt
			return errs.Wrap(err, "unable to scan groupPermission id")
		}
	}

	// The driver can defer a constraint violation to the result set rather than
	// returning it from the query, in which case Next() simply reports no row.
	// Without this the insert would look like a success with id 0.
	if err := rows.Err(); err != nil {
		groupPermission.CreatedAt = originalCreatedAt
		groupPermission.UpdatedAt = originalUpdatedAt
		return d.WrapSQLError(err, "unable to insert groupPermission")
	}

	return nil
}
