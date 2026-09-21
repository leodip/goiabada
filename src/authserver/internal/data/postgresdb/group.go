package postgresdb

import (
	"database/sql"
	"time"

	"github.com/huandu/go-sqlbuilder"
	"github.com/leodip/goiabada/authserver/internal/models"
	"github.com/leodip/goiabada/core/errs"
)

func (d *PostgresDatabase) CreateGroup(tx *sql.Tx, group *models.Group) error {
	now := time.Now().UTC()

	originalCreatedAt := group.CreatedAt
	originalUpdatedAt := group.UpdatedAt
	group.CreatedAt = sql.NullTime{Time: now, Valid: true}
	group.UpdatedAt = sql.NullTime{Time: now, Valid: true}

	groupStruct := sqlbuilder.NewStruct(new(models.Group)).
		For(sqlbuilder.PostgreSQL)

	insertBuilder := groupStruct.WithoutTag("pk").InsertInto(sqlbuilder.PostgreSQL.Quote("groups"), group)

	sql, args := insertBuilder.Build()
	sql = sql + " RETURNING id"

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
