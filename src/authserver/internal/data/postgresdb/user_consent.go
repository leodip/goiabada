package postgresdb

import (
	"database/sql"
	"time"

	"github.com/huandu/go-sqlbuilder"
	"github.com/leodip/goiabada/authserver/internal/models"
	"github.com/leodip/goiabada/core/errs"
)

func (d *PostgresDatabase) CreateUserConsent(tx *sql.Tx, userConsent *models.UserConsent) error {
	if userConsent.ClientId == 0 {
		return errs.New("client id must be greater than 0")
	}

	if userConsent.UserId == 0 {
		return errs.New("user id must be greater than 0")
	}

	now := time.Now().UTC()

	originalCreatedAt := userConsent.CreatedAt
	originalUpdatedAt := userConsent.UpdatedAt
	userConsent.CreatedAt = sql.NullTime{Time: now, Valid: true}
	userConsent.UpdatedAt = sql.NullTime{Time: now, Valid: true}

	userConsentStruct := sqlbuilder.NewStruct(new(models.UserConsent)).
		For(sqlbuilder.PostgreSQL)

	insertBuilder := userConsentStruct.WithoutTag("pk").InsertInto("user_consents", userConsent)

	sql, args := insertBuilder.Build()
	sql = sql + " RETURNING id"

	rows, err := d.QuerySql(tx, sql, args...)
	if err != nil {
		userConsent.CreatedAt = originalCreatedAt
		userConsent.UpdatedAt = originalUpdatedAt
		return errs.Wrap(err, "unable to insert userConsent")
	}
	defer func() { _ = rows.Close() }()

	if rows.Next() {
		err = rows.Scan(&userConsent.Id)
		if err != nil {
			userConsent.CreatedAt = originalCreatedAt
			userConsent.UpdatedAt = originalUpdatedAt
			return errs.Wrap(err, "unable to scan userConsent id")
		}
	}

	// The driver can defer a constraint violation to the result set rather than
	// returning it from the query, in which case Next() simply reports no row.
	// Without this the insert would look like a success with id 0.
	if err := rows.Err(); err != nil {
		userConsent.CreatedAt = originalCreatedAt
		userConsent.UpdatedAt = originalUpdatedAt
		return d.WrapSQLError(err, "unable to insert userConsent")
	}

	return nil
}
