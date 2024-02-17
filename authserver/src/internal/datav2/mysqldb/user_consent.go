package mysqldb

import (
	"database/sql"
	"time"

	"github.com/huandu/go-sqlbuilder"
	"github.com/leodip/goiabada/internal/entitiesv2"
	"github.com/pkg/errors"
)

func (d *MySQLDatabase) CreateUserConsent(tx *sql.Tx, userConsent *entitiesv2.UserConsent) error {

	if userConsent.ClientId == 0 {
		return errors.New("client id must be greater than 0")
	}

	if userConsent.UserId == 0 {
		return errors.New("user id must be greater than 0")
	}

	now := time.Now().UTC()

	originalCreatedAt := userConsent.CreatedAt
	originalUpdatedAt := userConsent.UpdatedAt
	userConsent.CreatedAt = sql.NullTime{Time: now, Valid: true}
	userConsent.UpdatedAt = sql.NullTime{Time: now, Valid: true}

	userConsentStruct := sqlbuilder.NewStruct(new(entitiesv2.UserConsent)).
		For(sqlbuilder.MySQL)

	insertBuilder := userConsentStruct.WithoutTag("pk").InsertInto("user_consents", userConsent)

	sql, args := insertBuilder.Build()
	result, err := d.execSql(tx, sql, args...)
	if err != nil {
		userConsent.CreatedAt = originalCreatedAt
		userConsent.UpdatedAt = originalUpdatedAt
		return errors.Wrap(err, "unable to insert userConsent")
	}

	id, err := result.LastInsertId()
	if err != nil {
		userConsent.CreatedAt = originalCreatedAt
		userConsent.UpdatedAt = originalUpdatedAt
		return errors.Wrap(err, "unable to get last insert id")
	}

	userConsent.Id = id
	return nil
}

func (d *MySQLDatabase) UpdateUserConsent(tx *sql.Tx, userConsent *entitiesv2.UserConsent) error {

	if userConsent.Id == 0 {
		return errors.New("can't update userConsent with id 0")
	}

	originalUpdatedAt := userConsent.UpdatedAt
	userConsent.UpdatedAt = sql.NullTime{Time: time.Now().UTC(), Valid: true}

	userConsentStruct := sqlbuilder.NewStruct(new(entitiesv2.UserConsent)).
		For(sqlbuilder.MySQL)

	updateBuilder := userConsentStruct.WithoutTag("pk").Update("user_consents", userConsent)
	updateBuilder.Where(updateBuilder.Equal("id", userConsent.Id))

	sql, args := updateBuilder.Build()
	_, err := d.execSql(tx, sql, args...)
	if err != nil {
		userConsent.UpdatedAt = originalUpdatedAt
		return errors.Wrap(err, "unable to update userConsent")
	}

	return nil
}

func (d *MySQLDatabase) getUserConsentCommon(tx *sql.Tx, selectBuilder *sqlbuilder.SelectBuilder,
	userConsentStruct *sqlbuilder.Struct) (*entitiesv2.UserConsent, error) {

	sql, args := selectBuilder.Build()
	rows, err := d.querySql(tx, sql, args...)
	if err != nil {
		return nil, errors.Wrap(err, "unable to query database")
	}
	defer rows.Close()

	var userConsent entitiesv2.UserConsent
	if rows.Next() {
		addr := userConsentStruct.Addr(&userConsent)
		err = rows.Scan(addr...)
		if err != nil {
			return nil, errors.Wrap(err, "unable to scan userConsent")
		}
		return &userConsent, nil
	}
	return nil, nil
}

func (d *MySQLDatabase) GetUserConsentById(tx *sql.Tx, userConsentId int64) (*entitiesv2.UserConsent, error) {

	if userConsentId <= 0 {
		return nil, errors.New("userConsent id must be greater than 0")
	}

	userConsentStruct := sqlbuilder.NewStruct(new(entitiesv2.UserConsent)).
		For(sqlbuilder.MySQL)

	selectBuilder := userConsentStruct.SelectFrom("user_consents")
	selectBuilder.Where(selectBuilder.Equal("id", userConsentId))

	userConsent, err := d.getUserConsentCommon(tx, selectBuilder, userConsentStruct)
	if err != nil {
		return nil, err
	}

	return userConsent, nil
}

func (d *MySQLDatabase) GetConsentByUserIdAndClientId(tx *sql.Tx, userId int64, clientId int64) (*entitiesv2.UserConsent, error) {
	if userId <= 0 {
		return nil, errors.New("user id must be greater than 0")
	}

	if clientId <= 0 {
		return nil, errors.New("client id must be greater than 0")
	}

	userConsentStruct := sqlbuilder.NewStruct(new(entitiesv2.UserConsent)).
		For(sqlbuilder.MySQL)

	selectBuilder := userConsentStruct.SelectFrom("user_consents")
	selectBuilder.Where(selectBuilder.Equal("user_id", userId))
	selectBuilder.Where(selectBuilder.Equal("client_id", clientId))

	userConsent, err := d.getUserConsentCommon(tx, selectBuilder, userConsentStruct)
	if err != nil {
		return nil, err
	}

	return userConsent, nil
}

func (d *MySQLDatabase) GetConsentsByUserId(tx *sql.Tx, userId int64) ([]entitiesv2.UserConsent, error) {
	if userId <= 0 {
		return nil, errors.New("user id must be greater than 0")
	}

	userConsentStruct := sqlbuilder.NewStruct(new(entitiesv2.UserConsent)).
		For(sqlbuilder.MySQL)

	selectBuilder := userConsentStruct.SelectFrom("user_consents")
	selectBuilder.Where(selectBuilder.Equal("user_id", userId))

	sql, args := selectBuilder.Build()
	rows, err := d.querySql(tx, sql, args...)
	if err != nil {
		return nil, errors.Wrap(err, "unable to query database")
	}
	defer rows.Close()

	var userConsents []entitiesv2.UserConsent
	for rows.Next() {
		var userConsent entitiesv2.UserConsent
		addr := userConsentStruct.Addr(&userConsent)
		err = rows.Scan(addr...)
		if err != nil {
			return nil, errors.Wrap(err, "unable to scan userConsent")
		}
		userConsents = append(userConsents, userConsent)
	}

	return userConsents, nil
}

func (d *MySQLDatabase) DeleteUserConsent(tx *sql.Tx, userConsentId int64) error {
	if userConsentId <= 0 {
		return errors.New("userConsentId must be greater than 0")
	}

	userConsentStruct := sqlbuilder.NewStruct(new(entitiesv2.UserConsent)).
		For(sqlbuilder.MySQL)

	deleteBuilder := userConsentStruct.DeleteFrom("user_consents")
	deleteBuilder.Where(deleteBuilder.Equal("id", userConsentId))

	sql, args := deleteBuilder.Build()
	_, err := d.execSql(tx, sql, args...)
	if err != nil {
		return errors.Wrap(err, "unable to delete userConsent")
	}

	return nil
}
