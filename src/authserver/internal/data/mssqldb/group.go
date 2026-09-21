package mssqldb

import (
	"database/sql"
	"strings"
	"time"

	"github.com/huandu/go-sqlbuilder"
	"github.com/leodip/goiabada/authserver/internal/models"
	"github.com/leodip/goiabada/core/errs"
)

func (d *MsSQLDatabase) CreateGroup(tx *sql.Tx, group *models.Group) error {
	now := time.Now().UTC()

	originalCreatedAt := group.CreatedAt
	originalUpdatedAt := group.UpdatedAt
	group.CreatedAt = sql.NullTime{Time: now, Valid: true}
	group.UpdatedAt = sql.NullTime{Time: now, Valid: true}

	groupStruct := sqlbuilder.NewStruct(new(models.Group)).
		For(sqlbuilder.SQLServer)

	insertBuilder := groupStruct.WithoutTag("pk").InsertInto(sqlbuilder.SQLServer.Quote("groups"), group)
	sql, args := insertBuilder.Build()

	parts := strings.SplitN(sql, "VALUES", 2)
	if len(parts) != 2 {
		return errs.New("unexpected SQL format from sqlbuilder")
	}
	sql = parts[0] + "OUTPUT INSERTED.id VALUES" + parts[1]

	rows, err := d.QuerySql(tx, sql, args...)
	if err != nil {
		group.CreatedAt = originalCreatedAt
		group.UpdatedAt = originalUpdatedAt
		return errs.Wrap(err, "unable to insert group")
	}
	defer func() { _ = rows.Close() }()

	if rows.Next() {
		err = rows.Scan(&group.Id)
		if err != nil {
			group.CreatedAt = originalCreatedAt
			group.UpdatedAt = originalUpdatedAt
			return errs.Wrap(err, "unable to scan group id")
		}
	}

	// The driver can defer a constraint violation to the result set rather than
	// returning it from the query, in which case Next() simply reports no row.
	// Without this the insert would look like a success with id 0.
	if err := rows.Err(); err != nil {
		group.CreatedAt = originalCreatedAt
		group.UpdatedAt = originalUpdatedAt
		return d.WrapSQLError(err, "unable to insert group")
	}

	return nil
}
