package mysqldb

import (
	"database/sql"
	"time"

	"github.com/huandu/go-sqlbuilder"
	"github.com/leodip/goiabada/internal/entitiesv2"
	"github.com/pkg/errors"
)

func (d *MySQLDatabase) CreateUserAttribute(tx *sql.Tx, userAttribute entitiesv2.UserAttribute) (*entitiesv2.UserAttribute, error) {

	if userAttribute.UserId == 0 {
		return nil, errors.New("userAttribute must have a user id")
	}

	now := time.Now().UTC()
	userAttribute.CreatedAt = now
	userAttribute.UpdatedAt = now

	userAttributeStruct := sqlbuilder.NewStruct(new(entitiesv2.UserAttribute)).
		For(sqlbuilder.MySQL)

	insertBuilder := userAttributeStruct.WithoutTag("pk").InsertInto("userAttributes", userAttribute)

	sql, args := insertBuilder.Build()
	result, err := d.execSql(tx, sql, args...)
	if err != nil {
		return nil, errors.Wrap(err, "unable to insert userAttribute")
	}

	id, err := result.LastInsertId()
	if err != nil {
		return nil, errors.Wrap(err, "unable to get last insert id")
	}
	userAttribute.Id = id

	return &userAttribute, nil
}

func (d *MySQLDatabase) UpdateUserAttribute(tx *sql.Tx, userAttribute entitiesv2.UserAttribute) (*entitiesv2.UserAttribute, error) {

	if userAttribute.Id == 0 {
		return nil, errors.New("can't update userAttribute with id 0")
	}

	userAttribute.UpdatedAt = time.Now().UTC()

	userAttributeStruct := sqlbuilder.NewStruct(new(entitiesv2.UserAttribute)).
		For(sqlbuilder.MySQL)

	updateBuilder := userAttributeStruct.WithoutTag("pk").Update("userAttributes", userAttribute)
	updateBuilder.Where(updateBuilder.Equal("id", userAttribute.Id))

	sql, args := updateBuilder.Build()
	_, err := d.execSql(tx, sql, args...)
	if err != nil {
		return nil, errors.Wrap(err, "unable to update userAttribute")
	}

	return &userAttribute, nil
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
		aaa := userAttributeStruct.Addr(&userAttribute)
		rows.Scan(aaa...)
	}

	return &userAttribute, nil
}

func (d *MySQLDatabase) GetUserAttributeById(tx *sql.Tx, userAttributeId int64) (*entitiesv2.UserAttribute, error) {

	if userAttributeId <= 0 {
		return nil, errors.New("userAttribute id must be greater than 0")
	}

	userAttributeStruct := sqlbuilder.NewStruct(new(entitiesv2.UserAttribute)).
		For(sqlbuilder.MySQL)

	selectBuilder := userAttributeStruct.SelectFrom("userAttributes")
	selectBuilder.Where(selectBuilder.Equal("id", userAttributeId))

	userAttribute, err := d.getUserAttributeCommon(tx, selectBuilder, userAttributeStruct)
	if err != nil {
		return nil, err
	}

	return userAttribute, nil
}
