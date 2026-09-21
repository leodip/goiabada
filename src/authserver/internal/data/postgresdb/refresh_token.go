package postgresdb

import (
	"database/sql"
	"time"

	"github.com/huandu/go-sqlbuilder"
	"github.com/leodip/goiabada/authserver/internal/models"
	"github.com/leodip/goiabada/core/errs"
)

func (d *PostgresDatabase) CreateRefreshToken(tx *sql.Tx, refreshToken *models.RefreshToken) error {
	now := time.Now().UTC()

	originalCreatedAt := refreshToken.CreatedAt
	originalUpdatedAt := refreshToken.UpdatedAt
	refreshToken.CreatedAt = sql.NullTime{Time: now, Valid: true}
	refreshToken.UpdatedAt = sql.NullTime{Time: now, Valid: true}

	refreshTokenStruct := sqlbuilder.NewStruct(new(models.RefreshToken)).
		For(sqlbuilder.PostgreSQL)

	insertBuilder := refreshTokenStruct.WithoutTag("pk").InsertInto("refresh_tokens", refreshToken)

	sql, args := insertBuilder.Build()
	sql = sql + " RETURNING id"

	rows, err := d.QuerySql(tx, sql, args...)
	if err != nil {
		refreshToken.CreatedAt = originalCreatedAt
		refreshToken.UpdatedAt = originalUpdatedAt
		return errs.Wrap(err, "unable to insert refreshToken")
	}
	defer func() { _ = rows.Close() }()

	if rows.Next() {
		err = rows.Scan(&refreshToken.Id)
		if err != nil {
			refreshToken.CreatedAt = originalCreatedAt
			refreshToken.UpdatedAt = originalUpdatedAt
			return errs.Wrap(err, "unable to scan refreshToken id")
		}
	}

	// The driver can defer a constraint violation to the result set rather than
	// returning it from the query, in which case Next() simply reports no row.
	// Without this the insert would look like a success with id 0.
	if err := rows.Err(); err != nil {
		refreshToken.CreatedAt = originalCreatedAt
		refreshToken.UpdatedAt = originalUpdatedAt
		return d.WrapSQLError(err, "unable to insert refreshToken")
	}

	return nil
}
