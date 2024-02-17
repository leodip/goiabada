package mysqldb

import (
	"database/sql"
	"time"

	"github.com/huandu/go-sqlbuilder"
	"github.com/leodip/goiabada/internal/entitiesv2"
	"github.com/pkg/errors"
)

func (d *MySQLDatabase) CreateUserGroup(tx *sql.Tx, userGroup *entitiesv2.UserGroup) error {

	if userGroup.UserId == 0 {
		return errors.New("can't create userGroup with user_id 0")
	}

	if userGroup.GroupId == 0 {
		return errors.New("can't create userGroup with group_id 0")
	}

	now := time.Now().UTC()

	originalCreatedAt := userGroup.CreatedAt
	originalUpdatedAt := userGroup.UpdatedAt
	userGroup.CreatedAt = sql.NullTime{Time: now, Valid: true}
	userGroup.UpdatedAt = sql.NullTime{Time: now, Valid: true}

	userGroupStruct := sqlbuilder.NewStruct(new(entitiesv2.UserGroup)).
		For(sqlbuilder.MySQL)

	insertBuilder := userGroupStruct.WithoutTag("pk").InsertInto("users_groups", userGroup)

	sql, args := insertBuilder.Build()
	result, err := d.execSql(tx, sql, args...)
	if err != nil {
		userGroup.CreatedAt = originalCreatedAt
		userGroup.UpdatedAt = originalUpdatedAt
		return errors.Wrap(err, "unable to insert userGroup")
	}

	id, err := result.LastInsertId()
	if err != nil {
		userGroup.CreatedAt = originalCreatedAt
		userGroup.UpdatedAt = originalUpdatedAt
		return errors.Wrap(err, "unable to get last insert id")
	}

	userGroup.Id = id
	return nil
}

func (d *MySQLDatabase) UpdateUserGroup(tx *sql.Tx, userGroup *entitiesv2.UserGroup) error {

	if userGroup.Id == 0 {
		return errors.New("can't update userGroup with id 0")
	}

	originalUpdatedAt := userGroup.UpdatedAt
	userGroup.UpdatedAt = sql.NullTime{Time: time.Now().UTC(), Valid: true}

	userGroupStruct := sqlbuilder.NewStruct(new(entitiesv2.UserGroup)).
		For(sqlbuilder.MySQL)

	updateBuilder := userGroupStruct.WithoutTag("pk").Update("users_groups", userGroup)
	updateBuilder.Where(updateBuilder.Equal("id", userGroup.Id))

	sql, args := updateBuilder.Build()
	_, err := d.execSql(tx, sql, args...)
	if err != nil {
		userGroup.UpdatedAt = originalUpdatedAt
		return errors.Wrap(err, "unable to update userGroup")
	}

	return nil
}

func (d *MySQLDatabase) getUserGroupCommon(tx *sql.Tx, selectBuilder *sqlbuilder.SelectBuilder,
	userGroupStruct *sqlbuilder.Struct) (*entitiesv2.UserGroup, error) {

	sql, args := selectBuilder.Build()
	rows, err := d.querySql(tx, sql, args...)
	if err != nil {
		return nil, errors.Wrap(err, "unable to query database")
	}
	defer rows.Close()

	var userGroup entitiesv2.UserGroup
	if rows.Next() {
		addr := userGroupStruct.Addr(&userGroup)
		err = rows.Scan(addr...)
		if err != nil {
			return nil, errors.Wrap(err, "unable to scan userGroup")
		}
		return &userGroup, nil
	}
	return nil, nil
}

func (d *MySQLDatabase) GetUserGroupById(tx *sql.Tx, userGroupId int64) (*entitiesv2.UserGroup, error) {

	if userGroupId <= 0 {
		return nil, errors.New("userGroup id must be greater than 0")
	}

	userGroupStruct := sqlbuilder.NewStruct(new(entitiesv2.UserGroup)).
		For(sqlbuilder.MySQL)

	selectBuilder := userGroupStruct.SelectFrom("users_groups")
	selectBuilder.Where(selectBuilder.Equal("id", userGroupId))

	userGroup, err := d.getUserGroupCommon(tx, selectBuilder, userGroupStruct)
	if err != nil {
		return nil, err
	}

	return userGroup, nil
}

func (d *MySQLDatabase) GetUserGroupByUserIdAndGroupId(tx *sql.Tx, userId, groupId int64) (*entitiesv2.UserGroup, error) {

	if userId <= 0 {
		return nil, errors.New("userId must be greater than 0")
	}

	if groupId <= 0 {
		return nil, errors.New("groupId must be greater than 0")
	}

	userGroupStruct := sqlbuilder.NewStruct(new(entitiesv2.UserGroup)).
		For(sqlbuilder.MySQL)

	selectBuilder := userGroupStruct.SelectFrom("users_groups")
	selectBuilder.Where(selectBuilder.Equal("user_id", userId))
	selectBuilder.Where(selectBuilder.Equal("group_id", groupId))

	userGroup, err := d.getUserGroupCommon(tx, selectBuilder, userGroupStruct)
	if err != nil {
		return nil, err
	}

	return userGroup, nil
}

func (d *MySQLDatabase) DeleteUserGroup(tx *sql.Tx, userGroupId int64) error {
	if userGroupId <= 0 {
		return errors.New("userGroupId must be greater than 0")
	}

	clientStruct := sqlbuilder.NewStruct(new(entitiesv2.UserGroup)).
		For(sqlbuilder.MySQL)

	deleteBuilder := clientStruct.DeleteFrom("users_groups")
	deleteBuilder.Where(deleteBuilder.Equal("id", userGroupId))

	sql, args := deleteBuilder.Build()
	_, err := d.execSql(tx, sql, args...)
	if err != nil {
		return errors.Wrap(err, "unable to delete userGroup")
	}

	return nil
}
