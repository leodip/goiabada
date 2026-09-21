package postgresdb

import (
	"database/sql"
	"time"

	"github.com/huandu/go-sqlbuilder"
	"github.com/leodip/goiabada/authserver/internal/models"
	"github.com/leodip/goiabada/core/errs"
)

func (d *PostgresDatabase) CreatePreRegistration(tx *sql.Tx, preRegistration *models.PreRegistration) error {
	now := time.Now().UTC()

	originalCreatedAt := preRegistration.CreatedAt
	originalUpdatedAt := preRegistration.UpdatedAt
	preRegistration.CreatedAt = sql.NullTime{Time: now, Valid: true}
	preRegistration.UpdatedAt = sql.NullTime{Time: now, Valid: true}

	preRegistrationStruct := sqlbuilder.NewStruct(new(models.PreRegistration)).
		For(sqlbuilder.PostgreSQL)

	insertBuilder := preRegistrationStruct.WithoutTag("pk").InsertInto("pre_registrations", preRegistration)

	sql, args := insertBuilder.Build()
	sql = sql + " RETURNING id"

	rows, err := d.QuerySql(tx, sql, args...)
	if err != nil {
		preRegistration.CreatedAt = originalCreatedAt
		preRegistration.UpdatedAt = originalUpdatedAt
		return errs.Wrap(err, "unable to insert preRegistration")
	}
	defer func() { _ = rows.Close() }()

	if rows.Next() {
		err = rows.Scan(&preRegistration.Id)
		if err != nil {
			preRegistration.CreatedAt = originalCreatedAt
			preRegistration.UpdatedAt = originalUpdatedAt
			return errs.Wrap(err, "unable to scan preRegistration id")
		}
	}

	// The driver can defer a constraint violation to the result set rather than
	// returning it from the query, in which case Next() simply reports no row.
	// Without this the insert would look like a success with id 0.
	if err := rows.Err(); err != nil {
		preRegistration.CreatedAt = originalCreatedAt
		preRegistration.UpdatedAt = originalUpdatedAt
		return d.WrapSQLError(err, "unable to insert preRegistration")
	}

	return nil
}
