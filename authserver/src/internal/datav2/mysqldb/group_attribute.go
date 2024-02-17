package mysqldb

import (
	"database/sql"
	"time"

	"github.com/huandu/go-sqlbuilder"
	"github.com/leodip/goiabada/internal/entitiesv2"
	"github.com/pkg/errors"
)

func (d *MySQLDatabase) CreateGroupAttribute(tx *sql.Tx, groupAttribute *entitiesv2.GroupAttribute) error {

	if groupAttribute.GroupId == 0 {
		return errors.New("can't create groupAttribute with group_id 0")
	}

	now := time.Now().UTC()

	originalCreatedAt := groupAttribute.CreatedAt
	originalUpdatedAt := groupAttribute.UpdatedAt
	groupAttribute.CreatedAt = sql.NullTime{Time: now, Valid: true}
	groupAttribute.UpdatedAt = sql.NullTime{Time: now, Valid: true}

	groupAttributeStruct := sqlbuilder.NewStruct(new(entitiesv2.GroupAttribute)).
		For(sqlbuilder.MySQL)

	insertBuilder := groupAttributeStruct.WithoutTag("pk").InsertInto("group_attributes", groupAttribute)

	sql, args := insertBuilder.Build()
	result, err := d.execSql(tx, sql, args...)
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

func (d *MySQLDatabase) UpdateGroupAttribute(tx *sql.Tx, groupAttribute *entitiesv2.GroupAttribute) error {

	if groupAttribute.Id == 0 {
		return errors.New("can't update groupAttribute with id 0")
	}

	originalUpdatedAt := groupAttribute.UpdatedAt
	groupAttribute.UpdatedAt = sql.NullTime{Time: time.Now().UTC(), Valid: true}

	groupAttributeStruct := sqlbuilder.NewStruct(new(entitiesv2.GroupAttribute)).
		For(sqlbuilder.MySQL)

	updateBuilder := groupAttributeStruct.WithoutTag("pk").Update("group_attributes", groupAttribute)
	updateBuilder.Where(updateBuilder.Equal("id", groupAttribute.Id))

	sql, args := updateBuilder.Build()
	_, err := d.execSql(tx, sql, args...)
	if err != nil {
		groupAttribute.UpdatedAt = originalUpdatedAt
		return errors.Wrap(err, "unable to update groupAttribute")
	}

	return nil
}

func (d *MySQLDatabase) getGroupAttributeCommon(tx *sql.Tx, selectBuilder *sqlbuilder.SelectBuilder,
	groupAttributeStruct *sqlbuilder.Struct) (*entitiesv2.GroupAttribute, error) {

	sql, args := selectBuilder.Build()
	rows, err := d.querySql(tx, sql, args...)
	if err != nil {
		return nil, errors.Wrap(err, "unable to query database")
	}
	defer rows.Close()

	var groupAttribute entitiesv2.GroupAttribute
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

func (d *MySQLDatabase) GetGroupAttributeById(tx *sql.Tx, groupAttributeId int64) (*entitiesv2.GroupAttribute, error) {

	if groupAttributeId <= 0 {
		return nil, errors.New("groupAttribute id must be greater than 0")
	}

	groupAttributeStruct := sqlbuilder.NewStruct(new(entitiesv2.GroupAttribute)).
		For(sqlbuilder.MySQL)

	selectBuilder := groupAttributeStruct.SelectFrom("group_attributes")
	selectBuilder.Where(selectBuilder.Equal("id", groupAttributeId))

	groupAttribute, err := d.getGroupAttributeCommon(tx, selectBuilder, groupAttributeStruct)
	if err != nil {
		return nil, err
	}

	return groupAttribute, nil
}

func (d *MySQLDatabase) GetGroupAttributesByGroupId(tx *sql.Tx, groupId int64) ([]entitiesv2.GroupAttribute, error) {

	if groupId <= 0 {
		return nil, errors.New("groupId must be greater than 0")
	}

	groupAttributeStruct := sqlbuilder.NewStruct(new(entitiesv2.GroupAttribute)).
		For(sqlbuilder.MySQL)

	selectBuilder := groupAttributeStruct.SelectFrom("group_attributes")
	selectBuilder.Where(selectBuilder.Equal("group_id", groupId))

	sql, args := selectBuilder.Build()
	rows, err := d.querySql(tx, sql, args...)
	if err != nil {
		return nil, errors.Wrap(err, "unable to query database")
	}
	defer rows.Close()

	var groupAttributes []entitiesv2.GroupAttribute
	for rows.Next() {
		var groupAttribute entitiesv2.GroupAttribute
		addr := groupAttributeStruct.Addr(&groupAttribute)
		err = rows.Scan(addr...)
		if err != nil {
			return nil, errors.Wrap(err, "unable to scan groupAttribute")
		}
		groupAttributes = append(groupAttributes, groupAttribute)
	}

	return groupAttributes, nil
}

func (d *MySQLDatabase) DeleteGroupAttribute(tx *sql.Tx, groupAttributeId int64) error {
	if groupAttributeId <= 0 {
		return errors.New("groupAttributeId must be greater than 0")
	}

	clientStruct := sqlbuilder.NewStruct(new(entitiesv2.GroupAttribute)).
		For(sqlbuilder.MySQL)

	deleteBuilder := clientStruct.DeleteFrom("group_attributes")
	deleteBuilder.Where(deleteBuilder.Equal("id", groupAttributeId))

	sql, args := deleteBuilder.Build()
	_, err := d.execSql(tx, sql, args...)
	if err != nil {
		return errors.Wrap(err, "unable to delete groupAttribute")
	}

	return nil
}
