package commondb

import (
	"context"
	"database/sql"
	"time"

	"github.com/huandu/go-sqlbuilder"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/errs"
)

func (d *Database) CreateGroupAttribute(ctx context.Context, tx *sql.Tx, groupAttribute *record.GroupAttribute) error {

	if groupAttribute.GroupId == 0 {
		return errs.New("can't create groupAttribute with group_id 0")
	}

	now := time.Now().UTC()

	originalCreatedAt := groupAttribute.CreatedAt
	originalUpdatedAt := groupAttribute.UpdatedAt
	groupAttribute.CreatedAt = sql.NullTime{Time: now, Valid: true}
	groupAttribute.UpdatedAt = sql.NullTime{Time: now, Valid: true}

	groupAttributeStruct := sqlbuilder.NewStruct(new(record.GroupAttribute)).
		For(d.Flavor)

	insertBuilder := groupAttributeStruct.WithoutTag("pk").InsertInto("group_attributes", groupAttribute)

	id, err := d.insertReturningId(ctx, tx, insertBuilder, "groupAttribute")
	if err != nil {
		groupAttribute.CreatedAt = originalCreatedAt
		groupAttribute.UpdatedAt = originalUpdatedAt
		return err
	}

	groupAttribute.Id = id
	return nil
}

func (d *Database) UpdateGroupAttribute(ctx context.Context, tx *sql.Tx, groupAttribute *record.GroupAttribute) error {

	if groupAttribute.Id == 0 {
		return errs.New("can't update groupAttribute with id 0")
	}

	originalUpdatedAt := groupAttribute.UpdatedAt
	groupAttribute.UpdatedAt = sql.NullTime{Time: time.Now().UTC(), Valid: true}

	groupAttributeStruct := sqlbuilder.NewStruct(new(record.GroupAttribute)).
		For(d.Flavor)

	updateBuilder := groupAttributeStruct.WithoutTag("pk").WithoutTag("dont-update").Update("group_attributes", groupAttribute)
	updateBuilder.Where(updateBuilder.Equal("id", groupAttribute.Id))

	sql, args := updateBuilder.Build()
	_, err := d.ExecSQL(ctx, tx, sql, args...)
	if err != nil {
		groupAttribute.UpdatedAt = originalUpdatedAt
		return errs.Wrap(err, "unable to update groupAttribute")
	}

	return nil
}

func (d *Database) getGroupAttributeCommon(ctx context.Context, tx *sql.Tx, selectBuilder *sqlbuilder.SelectBuilder,
	groupAttributeStruct *sqlbuilder.Struct) (*record.GroupAttribute, error) {

	sql, args := selectBuilder.Build()
	rows, err := d.QuerySQL(ctx, tx, sql, args...)
	if err != nil {
		return nil, errs.Wrap(err, "unable to query database")
	}
	defer func() { _ = rows.Close() }()

	var groupAttribute record.GroupAttribute
	if rows.Next() {
		addr := groupAttributeStruct.Addr(&groupAttribute)
		err = rows.Scan(addr...)
		if err != nil {
			return nil, errs.Wrap(err, "unable to scan groupAttribute")
		}
		return &groupAttribute, nil
	}
	if err := rows.Err(); err != nil {
		return nil, errs.Wrap(err, "unable to read query results")
	}

	return nil, nil
}

func (d *Database) GetGroupAttributeById(ctx context.Context, tx *sql.Tx, groupAttributeId int64) (*record.GroupAttribute, error) {

	groupAttributeStruct := sqlbuilder.NewStruct(new(record.GroupAttribute)).
		For(d.Flavor)

	selectBuilder := groupAttributeStruct.SelectFrom("group_attributes")
	selectBuilder.Where(selectBuilder.Equal("id", groupAttributeId))

	groupAttribute, err := d.getGroupAttributeCommon(ctx, tx, selectBuilder, groupAttributeStruct)
	if err != nil {
		return nil, err
	}

	return groupAttribute, nil
}

func (d *Database) GetGroupAttributesByGroupIds(ctx context.Context, tx *sql.Tx, groupIds []int64) ([]record.GroupAttribute, error) {

	if len(groupIds) == 0 {
		return nil, nil
	}

	var groupAttributes []record.GroupAttribute

	err := forEachIdBatch(groupIds, func(batch []int64) error {
		groupAttributeStruct := sqlbuilder.NewStruct(new(record.GroupAttribute)).
			For(d.Flavor)

		selectBuilder := groupAttributeStruct.SelectFrom("group_attributes")
		selectBuilder.Where(selectBuilder.In("group_id", sqlbuilder.Flatten(batch)...))

		sql, args := selectBuilder.Build()
		rows, err := d.QuerySQL(ctx, tx, sql, args...)
		if err != nil {
			return errs.Wrap(err, "unable to query database")
		}
		defer func() { _ = rows.Close() }()

		for rows.Next() {
			var groupAttribute record.GroupAttribute
			addr := groupAttributeStruct.Addr(&groupAttribute)
			err = rows.Scan(addr...)
			if err != nil {
				return errs.Wrap(err, "unable to scan groupAttribute")
			}
			groupAttributes = append(groupAttributes, groupAttribute)
		}

		if err := rows.Err(); err != nil {
			return errs.Wrap(err, "unable to read query results")
		}

		return nil
	})
	if err != nil {
		return nil, err
	}

	return groupAttributes, nil
}

func (d *Database) GetGroupAttributesByGroupId(ctx context.Context, tx *sql.Tx, groupId int64) ([]record.GroupAttribute, error) {

	groupAttributeStruct := sqlbuilder.NewStruct(new(record.GroupAttribute)).
		For(d.Flavor)

	selectBuilder := groupAttributeStruct.SelectFrom("group_attributes")
	selectBuilder.Where(selectBuilder.Equal("group_id", groupId))

	sql, args := selectBuilder.Build()
	rows, err := d.QuerySQL(ctx, tx, sql, args...)
	if err != nil {
		return nil, errs.Wrap(err, "unable to query database")
	}
	defer func() { _ = rows.Close() }()

	var groupAttributes []record.GroupAttribute
	for rows.Next() {
		var groupAttribute record.GroupAttribute
		addr := groupAttributeStruct.Addr(&groupAttribute)
		err = rows.Scan(addr...)
		if err != nil {
			return nil, errs.Wrap(err, "unable to scan groupAttribute")
		}
		groupAttributes = append(groupAttributes, groupAttribute)
	}

	if err := rows.Err(); err != nil {
		return nil, errs.Wrap(err, "unable to read query results")
	}

	return groupAttributes, nil
}

func (d *Database) DeleteGroupAttribute(ctx context.Context, tx *sql.Tx, groupAttributeId int64) error {

	clientStruct := sqlbuilder.NewStruct(new(record.GroupAttribute)).
		For(d.Flavor)

	deleteBuilder := clientStruct.DeleteFrom("group_attributes")
	deleteBuilder.Where(deleteBuilder.Equal("id", groupAttributeId))

	sql, args := deleteBuilder.Build()
	_, err := d.ExecSQL(ctx, tx, sql, args...)
	if err != nil {
		return errs.Wrap(err, "unable to delete groupAttribute")
	}

	return nil
}
