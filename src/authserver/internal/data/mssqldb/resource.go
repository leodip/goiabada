package mssqldb

import (
	"database/sql"
	"strings"
	"time"

	"github.com/huandu/go-sqlbuilder"
	"github.com/leodip/goiabada/authserver/internal/models"
	"github.com/leodip/goiabada/core/errs"
)

func (d *MsSQLDatabase) CreateResource(tx *sql.Tx, resource *models.Resource) error {
	now := time.Now().UTC()

	originalCreatedAt := resource.CreatedAt
	originalUpdatedAt := resource.UpdatedAt
	resource.CreatedAt = sql.NullTime{Time: now, Valid: true}
	resource.UpdatedAt = sql.NullTime{Time: now, Valid: true}

	resourceStruct := sqlbuilder.NewStruct(new(models.Resource)).
		For(sqlbuilder.SQLServer)

	insertBuilder := resourceStruct.WithoutTag("pk").InsertInto("resources", resource)
	sql, args := insertBuilder.Build()

	parts := strings.SplitN(sql, "VALUES", 2)
	if len(parts) != 2 {
		return errs.New("unexpected SQL format from sqlbuilder")
	}
	sql = parts[0] + "OUTPUT INSERTED.id VALUES" + parts[1]

	rows, err := d.QuerySql(tx, sql, args...)
	if err != nil {
		resource.CreatedAt = originalCreatedAt
		resource.UpdatedAt = originalUpdatedAt
		return errs.Wrap(err, "unable to insert resource")
	}
	defer func() { _ = rows.Close() }()

	if rows.Next() {
		err = rows.Scan(&resource.Id)
		if err != nil {
			resource.CreatedAt = originalCreatedAt
			resource.UpdatedAt = originalUpdatedAt
			return errs.Wrap(err, "unable to scan resource id")
		}
	}

	// The driver can defer a constraint violation to the result set rather than
	// returning it from the query, in which case Next() simply reports no row.
	// Without this the insert would look like a success with id 0.
	if err := rows.Err(); err != nil {
		resource.CreatedAt = originalCreatedAt
		resource.UpdatedAt = originalUpdatedAt
		return d.WrapSQLError(err, "unable to insert resource")
	}

	return nil
}
