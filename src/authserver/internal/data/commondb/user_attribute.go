package commondb

import (
	"context"
	"database/sql"
	"time"

	"github.com/huandu/go-sqlbuilder"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/errs"
)

func (d *Database) CreateUserAttribute(ctx context.Context, tx *sql.Tx, userAttribute *record.UserAttribute) error {

	if userAttribute.UserId == 0 {
		return errs.New("can't create userAttribute with user_id 0")
	}

	now := time.Now().UTC()

	originalCreatedAt := userAttribute.CreatedAt
	originalUpdatedAt := userAttribute.UpdatedAt
	userAttribute.CreatedAt = sql.NullTime{Time: now, Valid: true}
	userAttribute.UpdatedAt = sql.NullTime{Time: now, Valid: true}

	userAttributeStruct := sqlbuilder.NewStruct(new(record.UserAttribute)).
		For(d.Flavor)

	insertBuilder := userAttributeStruct.WithoutTag("pk").InsertInto("user_attributes", userAttribute)

	id, err := d.insertReturningId(ctx, tx, insertBuilder, "userAttribute")
	if err != nil {
		userAttribute.CreatedAt = originalCreatedAt
		userAttribute.UpdatedAt = originalUpdatedAt
		return err
	}

	userAttribute.Id = id
	return nil
}

func (d *Database) UpdateUserAttribute(ctx context.Context, tx *sql.Tx, userAttribute *record.UserAttribute) error {

	if userAttribute.Id == 0 {
		return errs.New("can't update userAttribute with id 0")
	}

	originalUpdatedAt := userAttribute.UpdatedAt
	userAttribute.UpdatedAt = sql.NullTime{Time: time.Now().UTC(), Valid: true}

	userAttributeStruct := sqlbuilder.NewStruct(new(record.UserAttribute)).
		For(d.Flavor)

	updateBuilder := userAttributeStruct.WithoutTag("pk").WithoutTag("dont-update").Update("user_attributes", userAttribute)
	updateBuilder.Where(updateBuilder.Equal("id", userAttribute.Id))

	sql, args := updateBuilder.Build()
	_, err := d.ExecSQL(ctx, tx, sql, args...)
	if err != nil {
		userAttribute.UpdatedAt = originalUpdatedAt
		return errs.Wrap(err, "unable to update userAttribute")
	}

	return nil
}

func (d *Database) getUserAttributeCommon(ctx context.Context, tx *sql.Tx, selectBuilder *sqlbuilder.SelectBuilder,
	userAttributeStruct *sqlbuilder.Struct) (*record.UserAttribute, error) {

	sql, args := selectBuilder.Build()
	rows, err := d.QuerySQL(ctx, tx, sql, args...)
	if err != nil {
		return nil, errs.Wrap(err, "unable to query database")
	}
	defer func() { _ = rows.Close() }()

	var userAttribute record.UserAttribute
	if rows.Next() {
		addr := userAttributeStruct.Addr(&userAttribute)
		err = rows.Scan(addr...)
		if err != nil {
			return nil, errs.Wrap(err, "unable to scan userAttribute")
		}
		return &userAttribute, nil
	}
	if err := rows.Err(); err != nil {
		return nil, errs.Wrap(err, "unable to read query results")
	}

	return nil, nil
}

func (d *Database) GetUserAttributeById(ctx context.Context, tx *sql.Tx, userAttributeId int64) (*record.UserAttribute, error) {

	userAttributeStruct := sqlbuilder.NewStruct(new(record.UserAttribute)).
		For(d.Flavor)

	selectBuilder := userAttributeStruct.SelectFrom("user_attributes")
	selectBuilder.Where(selectBuilder.Equal("id", userAttributeId))

	userAttribute, err := d.getUserAttributeCommon(ctx, tx, selectBuilder, userAttributeStruct)
	if err != nil {
		return nil, err
	}

	return userAttribute, nil
}

func (d *Database) GetUserAttributesByUserId(ctx context.Context, tx *sql.Tx, userId int64) ([]record.UserAttribute, error) {

	userAttributeStruct := sqlbuilder.NewStruct(new(record.UserAttribute)).
		For(d.Flavor)

	selectBuilder := userAttributeStruct.SelectFrom("user_attributes")
	selectBuilder.Where(selectBuilder.Equal("user_id", userId))

	sql, args := selectBuilder.Build()
	rows, err := d.QuerySQL(ctx, tx, sql, args...)
	if err != nil {
		return nil, errs.Wrap(err, "unable to query database")
	}
	defer func() { _ = rows.Close() }()

	var userAttributes []record.UserAttribute
	for rows.Next() {
		var userAttribute record.UserAttribute
		addr := userAttributeStruct.Addr(&userAttribute)
		err = rows.Scan(addr...)
		if err != nil {
			return nil, errs.Wrap(err, "unable to scan userAttribute")
		}
		userAttributes = append(userAttributes, userAttribute)
	}

	if err := rows.Err(); err != nil {
		return nil, errs.Wrap(err, "unable to read query results")
	}

	return userAttributes, nil
}

func (d *Database) DeleteUserAttribute(ctx context.Context, tx *sql.Tx, userAttributeId int64) error {

	clientStruct := sqlbuilder.NewStruct(new(record.UserAttribute)).
		For(d.Flavor)

	deleteBuilder := clientStruct.DeleteFrom("user_attributes")
	deleteBuilder.Where(deleteBuilder.Equal("id", userAttributeId))

	sql, args := deleteBuilder.Build()
	_, err := d.ExecSQL(ctx, tx, sql, args...)
	if err != nil {
		return errs.Wrap(err, "unable to delete userAttribute")
	}

	return nil
}
