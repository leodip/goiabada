package postgresdb

import (
	"database/sql"
	"time"

	"github.com/huandu/go-sqlbuilder"
	"github.com/leodip/goiabada/authserver/internal/models"
	"github.com/leodip/goiabada/core/errs"
)

func (d *PostgresDatabase) CreateUser(tx *sql.Tx, user *models.User) error {
	now := time.Now().UTC()

	originalCreatedAt := user.CreatedAt
	originalUpdatedAt := user.UpdatedAt
	user.CreatedAt = sql.NullTime{Time: now, Valid: true}
	user.UpdatedAt = sql.NullTime{Time: now, Valid: true}

	userStruct := sqlbuilder.NewStruct(new(models.User)).
		For(sqlbuilder.PostgreSQL)

	insertBuilder := userStruct.WithoutTag("pk").InsertInto("users", user)

	sql, args := insertBuilder.Build()
	sql = sql + " RETURNING id"

	rows, err := d.QuerySql(tx, sql, args...)
	if err != nil {
		user.CreatedAt = originalCreatedAt
		user.UpdatedAt = originalUpdatedAt
		return errs.Wrap(err, "unable to insert user")
	}
	defer func() { _ = rows.Close() }()

	if rows.Next() {
		err = rows.Scan(&user.Id)
		if err != nil {
			user.CreatedAt = originalCreatedAt
			user.UpdatedAt = originalUpdatedAt
			return errs.Wrap(err, "unable to scan user id")
		}
	}

	// The driver can defer a constraint violation to the result set rather than
	// returning it from the query, in which case Next() simply reports no row.
	// Without this the insert would look like a success with id 0.
	if err := rows.Err(); err != nil {
		user.CreatedAt = originalCreatedAt
		user.UpdatedAt = originalUpdatedAt
		return d.WrapSQLError(err, "unable to insert user")
	}

	return nil
}
