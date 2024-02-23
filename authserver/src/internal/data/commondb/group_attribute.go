package commondb

import (
	"database/sql"
	"time"

	"github.com/huandu/go-sqlbuilder"
	"github.com/leodip/goiabada/internal/entities"
	"github.com/pkg/errors"
)

func (d *CommonDatabase) CreateGroupAttribute(tx *sql.Tx, groupAttribute *entities.GroupAttribute) error {

	if groupAttribute.GroupId == 0 {
		return errors.WithStack(errors.New("can't create groupAttribute with group_id 0"))
	}

	now := time.Now().UTC()

	originalCreatedAt := groupAttribute.CreatedAt
	originalUpdatedAt := groupAttribute.UpdatedAt
	groupAttribute.CreatedAt = sql.NullTime{Time: now, Valid: true}
	groupAttribute.UpdatedAt = sql.NullTime{Time: now, Valid: true}

	groupAttributeStruct := sqlbuilder.NewStruct(new(entities.GroupAttribute)).
		For(d.Flavor)

	insertBuilder := groupAttributeStruct.WithoutTag("pk").InsertInto("group_attributes", groupAttribute)

	sql, args := insertBuilder.Build()
	result, err := d.ExecSql(tx, sql, args...)
	if err != nil {
		groupAttribute.CreatedAt = originalCreatedAt
		groupAttribute.UpdatedAt = originalUpdatedAt
		return errors.Wrap(err, "unable to insert groupAttribute")
	}

	id, err := result.LastInsertId()
	if err != nil {
		groupAttribute.CreatedAt = originalCreatedAt
		groupAttribute.UpdatedAt = originalUpdatedAt
		return errors.Wrap(err, "unable to get last insert id")
	}

	groupAttribute.Id = id
	return nil
}

func (d *CommonDatabase) UpdateGroupAttribute(tx *sql.Tx, groupAttribute *entities.GroupAttribute) error {

	if groupAttribute.Id == 0 {
		return errors.WithStack(errors.New("can't update groupAttribute with id 0"))
	}

	originalUpdatedAt := groupAttribute.UpdatedAt
	groupAttribute.UpdatedAt = sql.NullTime{Time: time.Now().UTC(), Valid: true}

	groupAttributeStruct := sqlbuilder.NewStruct(new(entities.GroupAttribute)).
		For(d.Flavor)

	updateBuilder := groupAttributeStruct.WithoutTag("pk").Update("group_attributes", groupAttribute)
	updateBuilder.Where(updateBuilder.Equal("id", groupAttribute.Id))

	sql, args := updateBuilder.Build()
	_, err := d.ExecSql(tx, sql, args...)
	if err != nil {
		groupAttribute.UpdatedAt = originalUpdatedAt
		return errors.Wrap(err, "unable to update groupAttribute")
	}

	return nil
}

func (d *CommonDatabase) getGroupAttributeCommon(tx *sql.Tx, selectBuilder *sqlbuilder.SelectBuilder,
	groupAttributeStruct *sqlbuilder.Struct) (*entities.GroupAttribute, error) {

	sql, args := selectBuilder.Build()
	rows, err := d.QuerySql(tx, sql, args...)
	if err != nil {
		return nil, errors.Wrap(err, "unable to query database")
	}
	defer rows.Close()

	var groupAttribute entities.GroupAttribute
	if rows.Next() {
		addr := groupAttributeStruct.Addr(&groupAttribute)
		err = rows.Scan(addr...)
		if err != nil {
			return nil, errors.Wrap(err, "unable to scan groupAttribute")
		}
		return &groupAttribute, nil
	}
	return nil, nil
}

func (d *CommonDatabase) GetGroupAttributeById(tx *sql.Tx, groupAttributeId int64) (*entities.GroupAttribute, error) {

	groupAttributeStruct := sqlbuilder.NewStruct(new(entities.GroupAttribute)).
		For(d.Flavor)

	selectBuilder := groupAttributeStruct.SelectFrom("group_attributes")
	selectBuilder.Where(selectBuilder.Equal("id", groupAttributeId))

	groupAttribute, err := d.getGroupAttributeCommon(tx, selectBuilder, groupAttributeStruct)
	if err != nil {
		return nil, err
	}

	return groupAttribute, nil
}

func (d *CommonDatabase) GetGroupAttributesByGroupIds(tx *sql.Tx, groupIds []int64) ([]entities.GroupAttribute, error) {

	if len(groupIds) == 0 {
		return nil, nil
	}

	groupAttributeStruct := sqlbuilder.NewStruct(new(entities.GroupAttribute)).
		For(d.Flavor)

	selectBuilder := groupAttributeStruct.SelectFrom("group_attributes")
	selectBuilder.Where(selectBuilder.In("group_id", sqlbuilder.Flatten(groupIds)...))

	sql, args := selectBuilder.Build()
	rows, err := d.QuerySql(tx, sql, args...)
	if err != nil {
		return nil, errors.Wrap(err, "unable to query database")
	}
	defer rows.Close()

	var groupAttributes []entities.GroupAttribute
	for rows.Next() {
		var groupAttribute entities.GroupAttribute
		addr := groupAttributeStruct.Addr(&groupAttribute)
		err = rows.Scan(addr...)
		if err != nil {
			return nil, errors.Wrap(err, "unable to scan groupAttribute")
		}
		groupAttributes = append(groupAttributes, groupAttribute)
	}

	return groupAttributes, nil
}

func (d *CommonDatabase) GetGroupAttributesByGroupId(tx *sql.Tx, groupId int64) ([]entities.GroupAttribute, error) {

	groupAttributeStruct := sqlbuilder.NewStruct(new(entities.GroupAttribute)).
		For(d.Flavor)

	selectBuilder := groupAttributeStruct.SelectFrom("group_attributes")
	selectBuilder.Where(selectBuilder.Equal("group_id", groupId))

	sql, args := selectBuilder.Build()
	rows, err := d.QuerySql(tx, sql, args...)
	if err != nil {
		return nil, errors.Wrap(err, "unable to query database")
	}
	defer rows.Close()

	var groupAttributes []entities.GroupAttribute
	for rows.Next() {
		var groupAttribute entities.GroupAttribute
		addr := groupAttributeStruct.Addr(&groupAttribute)
		err = rows.Scan(addr...)
		if err != nil {
			return nil, errors.Wrap(err, "unable to scan groupAttribute")
		}
		groupAttributes = append(groupAttributes, groupAttribute)
	}

	return groupAttributes, nil
}

func (d *CommonDatabase) DeleteGroupAttribute(tx *sql.Tx, groupAttributeId int64) error {

	clientStruct := sqlbuilder.NewStruct(new(entities.GroupAttribute)).
		For(d.Flavor)

	deleteBuilder := clientStruct.DeleteFrom("group_attributes")
	deleteBuilder.Where(deleteBuilder.Equal("id", groupAttributeId))

	sql, args := deleteBuilder.Build()
	_, err := d.ExecSql(tx, sql, args...)
	if err != nil {
		return errors.Wrap(err, "unable to delete groupAttribute")
	}

	return nil
}
