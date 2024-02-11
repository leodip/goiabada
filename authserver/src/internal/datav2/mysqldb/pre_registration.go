package mysqldb

import (
	"database/sql"
	"time"

	"github.com/huandu/go-sqlbuilder"
	"github.com/leodip/goiabada/internal/entitiesv2"
	"github.com/pkg/errors"
)

func (d *MySQLDatabase) CreatePreRegistration(tx *sql.Tx, preRegistration *entitiesv2.PreRegistration) error {

	now := time.Now().UTC()

	originalCreatedAt := preRegistration.CreatedAt
	originalUpdatedAt := preRegistration.UpdatedAt
	preRegistration.CreatedAt = now
	preRegistration.UpdatedAt = now

	preRegistrationStruct := sqlbuilder.NewStruct(new(entitiesv2.PreRegistration)).
		For(sqlbuilder.MySQL)

	insertBuilder := preRegistrationStruct.WithoutTag("pk").InsertInto("pre_registrations", preRegistration)

	sql, args := insertBuilder.Build()
	result, err := d.execSql(tx, sql, args...)
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

func (d *MySQLDatabase) UpdatePreRegistration(tx *sql.Tx, preRegistration *entitiesv2.PreRegistration) error {

	if preRegistration.Id == 0 {
		return errors.New("can't update preRegistration with id 0")
	}

	originalUpdatedAt := preRegistration.UpdatedAt
	preRegistration.UpdatedAt = time.Now().UTC()

	preRegistrationStruct := sqlbuilder.NewStruct(new(entitiesv2.PreRegistration)).
		For(sqlbuilder.MySQL)

	updateBuilder := preRegistrationStruct.WithoutTag("pk").Update("pre_registrations", preRegistration)
	updateBuilder.Where(updateBuilder.Equal("id", preRegistration.Id))

	sql, args := updateBuilder.Build()
	_, err := d.execSql(tx, sql, args...)
	if err != nil {
		preRegistration.UpdatedAt = originalUpdatedAt
		return errors.Wrap(err, "unable to update preRegistration")
	}

	return nil
}

func (d *MySQLDatabase) getPreRegistrationCommon(tx *sql.Tx, selectBuilder *sqlbuilder.SelectBuilder,
	preRegistrationStruct *sqlbuilder.Struct) (*entitiesv2.PreRegistration, error) {

	sql, args := selectBuilder.Build()
	rows, err := d.querySql(tx, sql, args...)
	if err != nil {
		return nil, errors.Wrap(err, "unable to query database")
	}
	defer rows.Close()

	var preRegistration entitiesv2.PreRegistration
	if rows.Next() {
		addr := preRegistrationStruct.Addr(&preRegistration)
		rows.Scan(addr...)
		return &preRegistration, nil
	}
	return nil, nil
}

func (d *MySQLDatabase) GetPreRegistrationById(tx *sql.Tx, preRegistrationId int64) (*entitiesv2.PreRegistration, error) {

	if preRegistrationId <= 0 {
		return nil, errors.New("preRegistration id must be greater than 0")
	}

	preRegistrationStruct := sqlbuilder.NewStruct(new(entitiesv2.PreRegistration)).
		For(sqlbuilder.MySQL)

	selectBuilder := preRegistrationStruct.SelectFrom("pre_registrations")
	selectBuilder.Where(selectBuilder.Equal("id", preRegistrationId))

	preRegistration, err := d.getPreRegistrationCommon(tx, selectBuilder, preRegistrationStruct)
	if err != nil {
		return nil, err
	}

	return preRegistration, nil
}

func (d *MySQLDatabase) DeletePreRegistration(tx *sql.Tx, preRegistrationId int64) error {
	if preRegistrationId <= 0 {
		return errors.New("preRegistration id must be greater than 0")
	}

	clientStruct := sqlbuilder.NewStruct(new(entitiesv2.PreRegistration)).
		For(sqlbuilder.MySQL)

	deleteBuilder := clientStruct.DeleteFrom("pre_registrations")
	deleteBuilder.Where(deleteBuilder.Equal("id", preRegistrationId))

	sql, args := deleteBuilder.Build()
	_, err := d.execSql(tx, sql, args...)
	if err != nil {
		return errors.Wrap(err, "unable to delete preRegistration")
	}

	return nil
}

func (d *MySQLDatabase) GetPreRegistrationByEmail(tx *sql.Tx, email string) (*entitiesv2.PreRegistration, error) {

	if email == "" {
		return nil, errors.New("email must not be empty")
	}

	preRegistrationStruct := sqlbuilder.NewStruct(new(entitiesv2.PreRegistration)).
		For(sqlbuilder.MySQL)

	selectBuilder := preRegistrationStruct.SelectFrom("pre_registrations")
	selectBuilder.Where(selectBuilder.Equal("email", email))

	preRegistration, err := d.getPreRegistrationCommon(tx, selectBuilder, preRegistrationStruct)
	if err != nil {
		return nil, err
	}

	return preRegistration, nil
}
