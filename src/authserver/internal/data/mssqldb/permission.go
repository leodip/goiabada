package mssqldb

import (
	"database/sql"
	"strings"
	"time"

	"github.com/huandu/go-sqlbuilder"
	"github.com/leodip/goiabada/authserver/internal/models"
	"github.com/leodip/goiabada/core/errs"
)

func (d *MsSQLDatabase) CreatePermission(tx *sql.Tx, permission *models.Permission) error {
	if permission.ResourceId == 0 {
		return errs.New("can't create permission with resource_id 0")
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
		return errs.New("unexpected SQL format from sqlbuilder")
	}
	sql = parts[0] + "OUTPUT INSERTED.id VALUES" + parts[1]

	rows, err := d.QuerySql(tx, sql, args...)
	if err != nil {
		permission.CreatedAt = originalCreatedAt
		permission.UpdatedAt = originalUpdatedAt
		return errs.Wrap(err, "unable to insert permission")
	}
	defer func() { _ = rows.Close() }()

	if rows.Next() {
		err = rows.Scan(&permission.Id)
		if err != nil {
			permission.CreatedAt = originalCreatedAt
			permission.UpdatedAt = originalUpdatedAt
			return errs.Wrap(err, "unable to scan permission id")
		}
	}

	// The driver can defer a constraint violation to the result set rather than
	// returning it from the query, in which case Next() simply reports no row.
	// Without this the insert would look like a success with id 0.
	if err := rows.Err(); err != nil {
		permission.CreatedAt = originalCreatedAt
		permission.UpdatedAt = originalUpdatedAt
		return d.WrapSQLError(err, "unable to insert permission")
	}

	return nil
}
