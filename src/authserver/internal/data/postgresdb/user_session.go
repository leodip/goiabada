package postgresdb

import (
	"database/sql"
	"time"

	"github.com/huandu/go-sqlbuilder"
	"github.com/leodip/goiabada/authserver/internal/models"
	"github.com/leodip/goiabada/core/errs"
)

func (d *PostgresDatabase) CreateUserSession(tx *sql.Tx, userSession *models.UserSession) error {
	if userSession.UserId == 0 {
		return errs.New("user id must be greater than 0")
	}

	now := time.Now().UTC()

	originalCreatedAt := userSession.CreatedAt
	originalUpdatedAt := userSession.UpdatedAt
	userSession.CreatedAt = sql.NullTime{Time: now, Valid: true}
	userSession.UpdatedAt = sql.NullTime{Time: now, Valid: true}

	userSessionStruct := sqlbuilder.NewStruct(new(models.UserSession)).
		For(sqlbuilder.PostgreSQL)

	insertBuilder := userSessionStruct.WithoutTag("pk").InsertInto("user_sessions", userSession)

	sql, args := insertBuilder.Build()
	sql = sql + " RETURNING id"

	rows, err := d.QuerySql(tx, sql, args...)
	if err != nil {
		userSession.CreatedAt = originalCreatedAt
		userSession.UpdatedAt = originalUpdatedAt
		return errs.Wrap(err, "unable to insert userSession")
	}
	defer func() { _ = rows.Close() }()

	if rows.Next() {
		err = rows.Scan(&userSession.Id)
		if err != nil {
			userSession.CreatedAt = originalCreatedAt
			userSession.UpdatedAt = originalUpdatedAt
			return errs.Wrap(err, "unable to scan userSession id")
		}
	}

	// The driver can defer a constraint violation to the result set rather than
	// returning it from the query, in which case Next() simply reports no row.
	// Without this the insert would look like a success with id 0.
	if err := rows.Err(); err != nil {
		userSession.CreatedAt = originalCreatedAt
		userSession.UpdatedAt = originalUpdatedAt
		return d.WrapSQLError(err, "unable to insert userSession")
	}

	return nil
}
