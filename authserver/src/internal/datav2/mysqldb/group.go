package mysqldb

import (
	"database/sql"
	"time"

	"github.com/huandu/go-sqlbuilder"
	"github.com/leodip/goiabada/internal/entitiesv2"
	"github.com/pkg/errors"
)

func (d *MySQLDatabase) CreateGroup(tx *sql.Tx, group *entitiesv2.Group) error {

	now := time.Now().UTC()

	originalCreatedAt := group.CreatedAt
	originalUpdatedAt := group.UpdatedAt
	group.CreatedAt = now
	group.UpdatedAt = now

	groupStruct := sqlbuilder.NewStruct(new(entitiesv2.Group)).
		For(sqlbuilder.MySQL)

	insertBuilder := groupStruct.WithoutTag("pk").InsertInto("`groups`", group)

	sql, args := insertBuilder.Build()
	result, err := d.execSql(tx, sql, args...)
	if err != nil {
		group.CreatedAt = originalCreatedAt
		group.UpdatedAt = originalUpdatedAt
		return errors.Wrap(err, "unable to insert group")
	}

	id, err := result.LastInsertId()
	if err != nil {
		group.CreatedAt = originalCreatedAt
		group.UpdatedAt = originalUpdatedAt
		return errors.Wrap(err, "unable to get last insert id")
	}

	group.Id = id
	return nil
}

func (d *MySQLDatabase) UpdateGroup(tx *sql.Tx, group *entitiesv2.Group) error {

	if group.Id == 0 {
		return errors.New("can't update group with id 0")
	}

	originalUpdatedAt := group.UpdatedAt
	group.UpdatedAt = time.Now().UTC()

	groupStruct := sqlbuilder.NewStruct(new(entitiesv2.Group)).
		For(sqlbuilder.MySQL)

	updateBuilder := groupStruct.WithoutTag("pk").Update("`groups`", group)
	updateBuilder.Where(updateBuilder.Equal("id", group.Id))

	sql, args := updateBuilder.Build()
	_, err := d.execSql(tx, sql, args...)
	if err != nil {
		group.UpdatedAt = originalUpdatedAt
		return errors.Wrap(err, "unable to update group")
	}

	return nil
}

func (d *MySQLDatabase) getGroupCommon(tx *sql.Tx, selectBuilder *sqlbuilder.SelectBuilder,
	groupStruct *sqlbuilder.Struct) (*entitiesv2.Group, error) {

	sql, args := selectBuilder.Build()
	rows, err := d.querySql(tx, sql, args...)
	if err != nil {
		return nil, errors.Wrap(err, "unable to query database")
	}
	defer rows.Close()

	var group entitiesv2.Group
	if rows.Next() {
		addr := groupStruct.Addr(&group)
		rows.Scan(addr...)
		return &group, nil
	}
	return nil, nil
}

func (d *MySQLDatabase) GetGroupById(tx *sql.Tx, groupId int64) (*entitiesv2.Group, error) {

	if groupId <= 0 {
		return nil, errors.New("group id must be greater than 0")
	}

	groupStruct := sqlbuilder.NewStruct(new(entitiesv2.Group)).
		For(sqlbuilder.MySQL)

	selectBuilder := groupStruct.SelectFrom("`groups`")
	selectBuilder.Where(selectBuilder.Equal("id", groupId))

	group, err := d.getGroupCommon(tx, selectBuilder, groupStruct)
	if err != nil {
		return nil, err
	}

	return group, nil
}

func (d *MySQLDatabase) GetGroupByGroupIdentifier(tx *sql.Tx, groupIdentifier string) (*entitiesv2.Group, error) {
	if groupIdentifier == "" {
		return nil, errors.New("group identifier must not be empty")
	}

	groupStruct := sqlbuilder.NewStruct(new(entitiesv2.Group)).
		For(sqlbuilder.MySQL)

	selectBuilder := groupStruct.SelectFrom("`groups`")
	selectBuilder.Where(selectBuilder.Equal("group_identifier", groupIdentifier))

	group, err := d.getGroupCommon(tx, selectBuilder, groupStruct)
	if err != nil {
		return nil, err
	}

	return group, nil
}

func (d *MySQLDatabase) GetAllGroups(tx *sql.Tx) ([]*entitiesv2.Group, error) {

	groupStruct := sqlbuilder.NewStruct(new(entitiesv2.Group)).
		For(sqlbuilder.MySQL)

	selectBuilder := groupStruct.SelectFrom("`groups`")

	sql, args := selectBuilder.Build()
	rows, err := d.querySql(tx, sql, args...)
	if err != nil {
		return nil, errors.Wrap(err, "unable to query database")
	}
	defer rows.Close()

	var groups []*entitiesv2.Group
	for rows.Next() {
		var group entitiesv2.Group
		addr := groupStruct.Addr(&group)
		rows.Scan(addr...)
		groups = append(groups, &group)
	}

	return groups, nil
}

func (d *MySQLDatabase) DeleteGroup(tx *sql.Tx, groupId int64) error {
	if groupId <= 0 {
		return errors.New("group id must be greater than 0")
	}

	clientStruct := sqlbuilder.NewStruct(new(entitiesv2.Group)).
		For(sqlbuilder.MySQL)

	deleteBuilder := clientStruct.DeleteFrom("`groups`")
	deleteBuilder.Where(deleteBuilder.Equal("id", groupId))

	sql, args := deleteBuilder.Build()
	_, err := d.execSql(tx, sql, args...)
	if err != nil {
		return errors.Wrap(err, "unable to delete group")
	}

	return nil
}