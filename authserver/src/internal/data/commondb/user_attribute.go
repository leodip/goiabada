package commondb

import (
	"database/sql"
	"time"

	"github.com/huandu/go-sqlbuilder"
	"github.com/leodip/goiabada/internal/entities"
	"github.com/pkg/errors"
)

func (d *CommonDatabase) CreateUserAttribute(tx *sql.Tx, userAttribute *entities.UserAttribute) error {

	if userAttribute.UserId == 0 {
		return errors.WithStack(errors.New("can't create userAttribute with user_id 0"))
	}

	now := time.Now().UTC()

	originalCreatedAt := userAttribute.CreatedAt
	originalUpdatedAt := userAttribute.UpdatedAt
	userAttribute.CreatedAt = sql.NullTime{Time: now, Valid: true}
	userAttribute.UpdatedAt = sql.NullTime{Time: now, Valid: true}

	userAttributeStruct := sqlbuilder.NewStruct(new(entities.UserAttribute)).
		For(d.Flavor)

	insertBuilder := userAttributeStruct.WithoutTag("pk").InsertInto("user_attributes", userAttribute)

	sql, args := insertBuilder.Build()
	result, err := d.ExecSql(tx, sql, args...)
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

func (d *CommonDatabase) UpdateUserAttribute(tx *sql.Tx, userAttribute *entities.UserAttribute) error {

	if userAttribute.Id == 0 {
		return errors.WithStack(errors.New("can't update userAttribute with id 0"))
	}

	originalUpdatedAt := userAttribute.UpdatedAt
	userAttribute.UpdatedAt = sql.NullTime{Time: time.Now().UTC(), Valid: true}

	userAttributeStruct := sqlbuilder.NewStruct(new(entities.UserAttribute)).
		For(d.Flavor)

	updateBuilder := userAttributeStruct.WithoutTag("pk").Update("user_attributes", userAttribute)
	updateBuilder.Where(updateBuilder.Equal("id", userAttribute.Id))

	sql, args := updateBuilder.Build()
	_, err := d.ExecSql(tx, sql, args...)
	if err != nil {
		userAttribute.UpdatedAt = originalUpdatedAt
		return errors.Wrap(err, "unable to update userAttribute")
	}

	return nil
}

func (d *CommonDatabase) getUserAttributeCommon(tx *sql.Tx, selectBuilder *sqlbuilder.SelectBuilder,
	userAttributeStruct *sqlbuilder.Struct) (*entities.UserAttribute, error) {

	sql, args := selectBuilder.Build()
	rows, err := d.QuerySql(tx, sql, args...)
	if err != nil {
		return nil, errors.Wrap(err, "unable to query database")
	}
	defer rows.Close()

	var userAttribute entities.UserAttribute
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

func (d *CommonDatabase) GetUserAttributeById(tx *sql.Tx, userAttributeId int64) (*entities.UserAttribute, error) {

	userAttributeStruct := sqlbuilder.NewStruct(new(entities.UserAttribute)).
		For(d.Flavor)

	selectBuilder := userAttributeStruct.SelectFrom("user_attributes")
	selectBuilder.Where(selectBuilder.Equal("id", userAttributeId))

	userAttribute, err := d.getUserAttributeCommon(tx, selectBuilder, userAttributeStruct)
	if err != nil {
		return nil, err
	}

	return userAttribute, nil
}

func (d *CommonDatabase) GetUserAttributesByUserId(tx *sql.Tx, userId int64) ([]entities.UserAttribute, error) {

	userAttributeStruct := sqlbuilder.NewStruct(new(entities.UserAttribute)).
		For(d.Flavor)

	selectBuilder := userAttributeStruct.SelectFrom("user_attributes")
	selectBuilder.Where(selectBuilder.Equal("user_id", userId))

	sql, args := selectBuilder.Build()
	rows, err := d.QuerySql(tx, sql, args...)
	if err != nil {
		return nil, errors.Wrap(err, "unable to query database")
	}
	defer rows.Close()

	var userAttributes []entities.UserAttribute
	for rows.Next() {
		var userAttribute entities.UserAttribute
		addr := userAttributeStruct.Addr(&userAttribute)
		err = rows.Scan(addr...)
		if err != nil {
			return nil, errors.Wrap(err, "unable to scan userAttribute")
		}
		userAttributes = append(userAttributes, userAttribute)
	}

	return userAttributes, nil
}

func (d *CommonDatabase) DeleteUserAttribute(tx *sql.Tx, userAttributeId int64) error {

	clientStruct := sqlbuilder.NewStruct(new(entities.UserAttribute)).
		For(d.Flavor)

	deleteBuilder := clientStruct.DeleteFrom("user_attributes")
	deleteBuilder.Where(deleteBuilder.Equal("id", userAttributeId))

	sql, args := deleteBuilder.Build()
	_, err := d.ExecSql(tx, sql, args...)
	if err != nil {
		return errors.Wrap(err, "unable to delete userAttribute")
	}

	return nil
}
