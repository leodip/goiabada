package commondb

import (
	"context"
	"database/sql"
	"time"

	"github.com/huandu/go-sqlbuilder"
	"github.com/leodip/goiabada/authserver/internal/models"
	"github.com/leodip/goiabada/core/errs"
)

func (d *CommonDatabase) CreateUserGroup(ctx context.Context, tx *sql.Tx, userGroup *models.UserGroup) error {

	if userGroup.UserId == 0 {
		return errs.New("can't create userGroup with user_id 0")
	}

	if userGroup.GroupId == 0 {
		return errs.New("can't create userGroup with group_id 0")
	}

	now := time.Now().UTC()

	originalCreatedAt := userGroup.CreatedAt
	originalUpdatedAt := userGroup.UpdatedAt
	userGroup.CreatedAt = sql.NullTime{Time: now, Valid: true}
	userGroup.UpdatedAt = sql.NullTime{Time: now, Valid: true}

	userGroupStruct := sqlbuilder.NewStruct(new(models.UserGroup)).
		For(d.Flavor)

	insertBuilder := userGroupStruct.WithoutTag("pk").InsertInto("users_groups", userGroup)

	id, err := d.insertReturningId(ctx, tx, insertBuilder, "userGroup")
	if err != nil {
		userGroup.CreatedAt = originalCreatedAt
		userGroup.UpdatedAt = originalUpdatedAt
		return err
	}

	userGroup.Id = id
	return nil
}

func (d *CommonDatabase) UpdateUserGroup(ctx context.Context, tx *sql.Tx, userGroup *models.UserGroup) error {

	if userGroup.Id == 0 {
		return errs.New("can't update userGroup with id 0")
	}

	originalUpdatedAt := userGroup.UpdatedAt
	userGroup.UpdatedAt = sql.NullTime{Time: time.Now().UTC(), Valid: true}

	userGroupStruct := sqlbuilder.NewStruct(new(models.UserGroup)).
		For(d.Flavor)

	updateBuilder := userGroupStruct.WithoutTag("pk").WithoutTag("dont-update").Update("users_groups", userGroup)
	updateBuilder.Where(updateBuilder.Equal("id", userGroup.Id))

	sql, args := updateBuilder.Build()
	_, err := d.ExecSql(ctx, tx, sql, args...)
	if err != nil {
		userGroup.UpdatedAt = originalUpdatedAt
		return errs.Wrap(err, "unable to update userGroup")
	}

	return nil
}

func (d *CommonDatabase) getUserGroupCommon(ctx context.Context, tx *sql.Tx, selectBuilder *sqlbuilder.SelectBuilder,
	userGroupStruct *sqlbuilder.Struct) (*models.UserGroup, error) {

	sql, args := selectBuilder.Build()
	rows, err := d.QuerySql(ctx, tx, sql, args...)
	if err != nil {
		return nil, errs.Wrap(err, "unable to query database")
	}
	defer func() { _ = rows.Close() }()

	var userGroup models.UserGroup
	if rows.Next() {
		addr := userGroupStruct.Addr(&userGroup)
		err = rows.Scan(addr...)
		if err != nil {
			return nil, errs.Wrap(err, "unable to scan userGroup")
		}
		return &userGroup, nil
	}
	if err := rows.Err(); err != nil {
		return nil, errs.Wrap(err, "unable to read query results")
	}

	return nil, nil
}

func (d *CommonDatabase) GetUserGroupById(ctx context.Context, tx *sql.Tx, userGroupId int64) (*models.UserGroup, error) {

	userGroupStruct := sqlbuilder.NewStruct(new(models.UserGroup)).
		For(d.Flavor)

	selectBuilder := userGroupStruct.SelectFrom("users_groups")
	selectBuilder.Where(selectBuilder.Equal("id", userGroupId))

	userGroup, err := d.getUserGroupCommon(ctx, tx, selectBuilder, userGroupStruct)
	if err != nil {
		return nil, err
	}

	return userGroup, nil
}

func (d *CommonDatabase) GetUserGroupsByUserIds(ctx context.Context, tx *sql.Tx, userIds []int64) ([]models.UserGroup, error) {

	if len(userIds) == 0 {
		return nil, nil
	}

	var userGroups []models.UserGroup

	err := forEachIdBatch(userIds, func(batch []int64) error {
		userGroupStruct := sqlbuilder.NewStruct(new(models.UserGroup)).
			For(d.Flavor)

		selectBuilder := userGroupStruct.SelectFrom("users_groups")
		selectBuilder.Where(selectBuilder.In("user_id", sqlbuilder.Flatten(batch)...))

		sql, args := selectBuilder.Build()
		rows, err := d.QuerySql(ctx, tx, sql, args...)
		if err != nil {
			return errs.Wrap(err, "unable to query database")
		}
		defer func() { _ = rows.Close() }()

		for rows.Next() {
			var userGroup models.UserGroup
			addr := userGroupStruct.Addr(&userGroup)
			err = rows.Scan(addr...)
			if err != nil {
				return errs.Wrap(err, "unable to scan userGroup")
			}
			userGroups = append(userGroups, userGroup)
		}

		if err := rows.Err(); err != nil {
			return errs.Wrap(err, "unable to read query results")
		}

		return nil
	})
	if err != nil {
		return nil, err
	}

	return userGroups, nil
}

func (d *CommonDatabase) GetUserGroupsByUserId(ctx context.Context, tx *sql.Tx, userId int64) ([]models.UserGroup, error) {

	userGroupStruct := sqlbuilder.NewStruct(new(models.UserGroup)).
		For(d.Flavor)

	selectBuilder := userGroupStruct.SelectFrom("users_groups")
	selectBuilder.Where(selectBuilder.Equal("user_id", userId))

	sql, args := selectBuilder.Build()
	rows, err := d.QuerySql(ctx, tx, sql, args...)
	if err != nil {
		return nil, errs.Wrap(err, "unable to query database")
	}
	defer func() { _ = rows.Close() }()

	var userGroups []models.UserGroup
	for rows.Next() {
		var userGroup models.UserGroup
		addr := userGroupStruct.Addr(&userGroup)
		err = rows.Scan(addr...)
		if err != nil {
			return nil, errs.Wrap(err, "unable to scan userGroup")
		}
		userGroups = append(userGroups, userGroup)
	}

	if err := rows.Err(); err != nil {
		return nil, errs.Wrap(err, "unable to read query results")
	}

	return userGroups, nil
}

func (d *CommonDatabase) GetUserGroupByUserIdAndGroupId(ctx context.Context, tx *sql.Tx, userId, groupId int64) (*models.UserGroup, error) {

	userGroupStruct := sqlbuilder.NewStruct(new(models.UserGroup)).
		For(d.Flavor)

	selectBuilder := userGroupStruct.SelectFrom("users_groups")
	selectBuilder.Where(selectBuilder.Equal("user_id", userId))
	selectBuilder.Where(selectBuilder.Equal("group_id", groupId))

	userGroup, err := d.getUserGroupCommon(ctx, tx, selectBuilder, userGroupStruct)
	if err != nil {
		return nil, err
	}

	return userGroup, nil
}

func (d *CommonDatabase) DeleteUserGroup(ctx context.Context, tx *sql.Tx, userGroupId int64) error {

	clientStruct := sqlbuilder.NewStruct(new(models.UserGroup)).
		For(d.Flavor)

	deleteBuilder := clientStruct.DeleteFrom("users_groups")
	deleteBuilder.Where(deleteBuilder.Equal("id", userGroupId))

	sql, args := deleteBuilder.Build()
	_, err := d.ExecSql(ctx, tx, sql, args...)
	if err != nil {
		return errs.Wrap(err, "unable to delete userGroup")
	}

	return nil
}
