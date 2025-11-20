package commondb

import (
	"database/sql"
	"time"

	"github.com/huandu/go-sqlbuilder"
	"github.com/leodip/goiabada/core/models"
	"github.com/pkg/errors"
)

func (d *CommonDatabase) CreatePreRegistration(tx *sql.Tx, preRegistration *models.PreRegistration) error {

	now := time.Now().UTC()

	originalCreatedAt := preRegistration.CreatedAt
	originalUpdatedAt := preRegistration.UpdatedAt
	preRegistration.CreatedAt = sql.NullTime{Time: now, Valid: true}
	preRegistration.UpdatedAt = sql.NullTime{Time: now, Valid: true}

	preRegistrationStruct := sqlbuilder.NewStruct(new(models.PreRegistration)).
		For(d.Flavor)

	insertBuilder := preRegistrationStruct.WithoutTag("pk").InsertInto("pre_registrations", preRegistration)

	sql, args := insertBuilder.Build()
	result, err := d.ExecSql(tx, sql, args...)
	if err != nil {
		preRegistration.CreatedAt = originalCreatedAt
		preRegistration.UpdatedAt = originalUpdatedAt
		return errors.Wrap(err, "unable to insert preRegistration")
	}

	id, err := result.LastInsertId()
	if err != nil {
		preRegistration.CreatedAt = originalCreatedAt
		preRegistration.UpdatedAt = originalUpdatedAt
		return errors.Wrap(err, "unable to get last insert id")
	}

	preRegistration.Id = id
	return nil
}

func (d *CommonDatabase) UpdatePreRegistration(tx *sql.Tx, preRegistration *models.PreRegistration) error {

	if preRegistration.Id == 0 {
		return errors.WithStack(errors.New("can't update preRegistration with id 0"))
	}

	originalUpdatedAt := preRegistration.UpdatedAt
	preRegistration.UpdatedAt = sql.NullTime{Time: time.Now().UTC(), Valid: true}

	preRegistrationStruct := sqlbuilder.NewStruct(new(models.PreRegistration)).
		For(d.Flavor)

	updateBuilder := preRegistrationStruct.WithoutTag("pk").WithoutTag("dont-update").Update("pre_registrations", preRegistration)
	updateBuilder.Where(updateBuilder.Equal("id", preRegistration.Id))

	sql, args := updateBuilder.Build()
	_, err := d.ExecSql(tx, sql, args...)
	if err != nil {
		preRegistration.UpdatedAt = originalUpdatedAt
		return errors.Wrap(err, "unable to update preRegistration")
	}

	return nil
}

func (d *CommonDatabase) getPreRegistrationCommon(tx *sql.Tx, selectBuilder *sqlbuilder.SelectBuilder,
	preRegistrationStruct *sqlbuilder.Struct) (*models.PreRegistration, error) {

	sql, args := selectBuilder.Build()
	rows, err := d.QuerySql(tx, sql, args...)
	if err != nil {
		return nil, errors.Wrap(err, "unable to query database")
	}
	defer func() { _ = rows.Close() }()

	var preRegistration models.PreRegistration
	if rows.Next() {
		addr := preRegistrationStruct.Addr(&preRegistration)
		err = rows.Scan(addr...)
		if err != nil {
			return nil, errors.Wrap(err, "unable to scan preRegistration")
		}
		return &preRegistration, nil
	}
	return nil, nil
}

func (d *CommonDatabase) GetPreRegistrationById(tx *sql.Tx, preRegistrationId int64) (*models.PreRegistration, error) {

	preRegistrationStruct := sqlbuilder.NewStruct(new(models.PreRegistration)).
		For(d.Flavor)

	selectBuilder := preRegistrationStruct.SelectFrom("pre_registrations")
	selectBuilder.Where(selectBuilder.Equal("id", preRegistrationId))

	preRegistration, err := d.getPreRegistrationCommon(tx, selectBuilder, preRegistrationStruct)
	if err != nil {
		return nil, err
	}

	return preRegistration, nil
}

func (d *CommonDatabase) DeletePreRegistration(tx *sql.Tx, preRegistrationId int64) error {

	clientStruct := sqlbuilder.NewStruct(new(models.PreRegistration)).
		For(d.Flavor)

	deleteBuilder := clientStruct.DeleteFrom("pre_registrations")
	deleteBuilder.Where(deleteBuilder.Equal("id", preRegistrationId))

	sql, args := deleteBuilder.Build()
	_, err := d.ExecSql(tx, sql, args...)
	if err != nil {
		return errors.Wrap(err, "unable to delete preRegistration")
	}

	return nil
}

func (d *CommonDatabase) GetPreRegistrationByEmail(tx *sql.Tx, email string) (*models.PreRegistration, error) {

	preRegistrationStruct := sqlbuilder.NewStruct(new(models.PreRegistration)).
		For(d.Flavor)

	selectBuilder := preRegistrationStruct.SelectFrom("pre_registrations")
	selectBuilder.Where(selectBuilder.Equal("email", email))

	preRegistration, err := d.getPreRegistrationCommon(tx, selectBuilder, preRegistrationStruct)
	if err != nil {
		return nil, err
	}

	return preRegistration, nil
}
