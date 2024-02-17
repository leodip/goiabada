package mysqldb

import (
	"database/sql"
	"time"

	"github.com/huandu/go-sqlbuilder"
	"github.com/leodip/goiabada/internal/entitiesv2"
	"github.com/pkg/errors"
)

func (d *MySQLDatabase) CreateUserAttribute(tx *sql.Tx, userAttribute *entitiesv2.UserAttribute) error {

	if userAttribute.UserId == 0 {
		return errors.New("can't create userAttribute with user_id 0")
	}

	now := time.Now().UTC()

	originalCreatedAt := userAttribute.CreatedAt
	originalUpdatedAt := userAttribute.UpdatedAt
	userAttribute.CreatedAt = sql.NullTime{Time: now, Valid: true}
	userAttribute.UpdatedAt = sql.NullTime{Time: now, Valid: true}

	userAttributeStruct := sqlbuilder.NewStruct(new(entitiesv2.UserAttribute)).
		For(sqlbuilder.MySQL)

	insertBuilder := userAttributeStruct.WithoutTag("pk").InsertInto("user_attributes", userAttribute)

	sql, args := insertBuilder.Build()
	result, err := d.execSql(tx, sql, args...)
	if err != nil {
		userAttribute.CreatedAt = originalCreatedAt
		userAttribute.UpdatedAt = originalUpdatedAt
		return errors.Wrap(err, "unable to insert userAttribute")
	}

	id, err := result.LastInsertId()
	if err != nil {
		userAttribute.CreatedAt = originalCreatedAt
		userAttribute.UpdatedAt = originalUpdatedAt
		return errors.Wrap(err, "unable to get last insert id")
	}

	userAttribute.Id = id
	return nil
}

func (d *MySQLDatabase) UpdateUserAttribute(tx *sql.Tx, userAttribute *entitiesv2.UserAttribute) error {

	if userAttribute.Id == 0 {
		return errors.New("can't update userAttribute with id 0")
	}

	originalUpdatedAt := userAttribute.UpdatedAt
	userAttribute.UpdatedAt = sql.NullTime{Time: time.Now().UTC(), Valid: true}

	userAttributeStruct := sqlbuilder.NewStruct(new(entitiesv2.UserAttribute)).
		For(sqlbuilder.MySQL)

	updateBuilder := userAttributeStruct.WithoutTag("pk").Update("user_attributes", userAttribute)
	updateBuilder.Where(updateBuilder.Equal("id", userAttribute.Id))

	sql, args := updateBuilder.Build()
	_, err := d.execSql(tx, sql, args...)
	if err != nil {
		userAttribute.UpdatedAt = originalUpdatedAt
		return errors.Wrap(err, "unable to update userAttribute")
	}

	return nil
}

func (d *MySQLDatabase) getUserAttributeCommon(tx *sql.Tx, selectBuilder *sqlbuilder.SelectBuilder,
	userAttributeStruct *sqlbuilder.Struct) (*entitiesv2.UserAttribute, error) {

	sql, args := selectBuilder.Build()
	rows, err := d.querySql(tx, sql, args...)
	if err != nil {
		return nil, errors.Wrap(err, "unable to query database")
	}
	defer rows.Close()

	var userAttribute entitiesv2.UserAttribute
	if rows.Next() {
		addr := userAttributeStruct.Addr(&userAttribute)
		err = rows.Scan(addr...)
		if err != nil {
			return nil, errors.Wrap(err, "unable to scan userAttribute")
		}
		return &userAttribute, nil
	}
	return nil, nil
}

func (d *MySQLDatabase) GetUserAttributeById(tx *sql.Tx, userAttributeId int64) (*entitiesv2.UserAttribute, error) {

	if userAttributeId <= 0 {
		return nil, errors.New("userAttribute id must be greater than 0")
	}

	userAttributeStruct := sqlbuilder.NewStruct(new(entitiesv2.UserAttribute)).
		For(sqlbuilder.MySQL)

	selectBuilder := userAttributeStruct.SelectFrom("user_attributes")
	selectBuilder.Where(selectBuilder.Equal("id", userAttributeId))

	userAttribute, err := d.getUserAttributeCommon(tx, selectBuilder, userAttributeStruct)
	if err != nil {
		return nil, err
	}

	return userAttribute, nil
}

func (d *MySQLDatabase) DeleteUserAttribute(tx *sql.Tx, userAttributeId int64) error {
	if userAttributeId <= 0 {
		return errors.New("userAttributeId must be greater than 0")
	}

	clientStruct := sqlbuilder.NewStruct(new(entitiesv2.UserAttribute)).
		For(sqlbuilder.MySQL)

	deleteBuilder := clientStruct.DeleteFrom("user_attributes")
	deleteBuilder.Where(deleteBuilder.Equal("id", userAttributeId))

	sql, args := deleteBuilder.Build()
	_, err := d.execSql(tx, sql, args...)
	if err != nil {
		return errors.Wrap(err, "unable to delete userAttribute")
	}

	return nil
}
