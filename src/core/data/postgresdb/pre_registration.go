package postgresdb

import (
	"database/sql"
	"time"

	"github.com/huandu/go-sqlbuilder"
	"github.com/leodip/goiabada/core/models"
	"github.com/pkg/errors"
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

	rows, err := d.CommonDB.QuerySql(tx, sql, args...)
	if err != nil {
		preRegistration.CreatedAt = originalCreatedAt
		preRegistration.UpdatedAt = originalUpdatedAt
		return errors.Wrap(err, "unable to insert preRegistration")
	}
	defer rows.Close()

	if rows.Next() {
		err = rows.Scan(&preRegistration.Id)
		if err != nil {
			preRegistration.CreatedAt = originalCreatedAt
			preRegistration.UpdatedAt = originalUpdatedAt
			return errors.Wrap(err, "unable to scan preRegistration id")
		}
	}

	return nil
}

func (d *PostgresDatabase) UpdatePreRegistration(tx *sql.Tx, preRegistration *models.PreRegistration) error {
	return d.CommonDB.UpdatePreRegistration(tx, preRegistration)
}

func (d *PostgresDatabase) GetPreRegistrationById(tx *sql.Tx, preRegistrationId int64) (*models.PreRegistration, error) {
	return d.CommonDB.GetPreRegistrationById(tx, preRegistrationId)
}

func (d *PostgresDatabase) DeletePreRegistration(tx *sql.Tx, preRegistrationId int64) error {
	return d.CommonDB.DeletePreRegistration(tx, preRegistrationId)
}

func (d *PostgresDatabase) GetPreRegistrationByEmail(tx *sql.Tx, email string) (*models.PreRegistration, error) {
	return d.CommonDB.GetPreRegistrationByEmail(tx, email)
}
