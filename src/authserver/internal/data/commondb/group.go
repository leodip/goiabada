package commondb

import (
	"context"
	"database/sql"
	"time"

	"github.com/huandu/go-sqlbuilder"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/errs"
)

func (d *Database) CreateGroup(ctx context.Context, tx *sql.Tx, group *record.Group) error {

	now := time.Now().UTC()

	originalCreatedAt := group.CreatedAt
	originalUpdatedAt := group.UpdatedAt
	group.CreatedAt = sql.NullTime{Time: now, Valid: true}
	group.UpdatedAt = sql.NullTime{Time: now, Valid: true}

	groupStruct := sqlbuilder.NewStruct(new(record.Group)).
		For(d.Flavor)

	insertBuilder := groupStruct.WithoutTag("pk").InsertInto(d.Flavor.Quote("groups"), group)

	id, err := d.insertReturningId(ctx, tx, insertBuilder, "group")
	if err != nil {
		group.CreatedAt = originalCreatedAt
		group.UpdatedAt = originalUpdatedAt
		return err
	}

	group.Id = id
	return nil
}

func (d *Database) UpdateGroup(ctx context.Context, tx *sql.Tx, group *record.Group) error {

	if group.Id == 0 {
		return errs.New("can't update group with id 0")
	}

	originalUpdatedAt := group.UpdatedAt
	group.UpdatedAt = sql.NullTime{Time: time.Now().UTC(), Valid: true}

	groupStruct := sqlbuilder.NewStruct(new(record.Group)).
		For(d.Flavor)

	updateBuilder := groupStruct.WithoutTag("pk").WithoutTag("dont-update").Update(d.Flavor.Quote("groups"), group)
	updateBuilder.Where(updateBuilder.Equal("id", group.Id))

	sql, args := updateBuilder.Build()
	_, err := d.ExecSQL(ctx, tx, sql, args...)
	if err != nil {
		group.UpdatedAt = originalUpdatedAt
		return errs.Wrap(err, "unable to update group")
	}

	return nil
}

func (d *Database) getGroupCommon(ctx context.Context, tx *sql.Tx, selectBuilder *sqlbuilder.SelectBuilder,
	groupStruct *sqlbuilder.Struct) (*record.Group, error) {

	sql, args := selectBuilder.Build()
	rows, err := d.QuerySQL(ctx, tx, sql, args...)
	if err != nil {
		return nil, errs.Wrap(err, "unable to query database")
	}
	defer func() { _ = rows.Close() }()

	var group record.Group
	if rows.Next() {
		addr := groupStruct.Addr(&group)
		err = rows.Scan(addr...)
		if err != nil {
			return nil, errs.Wrap(err, "unable to scan group")
		}
		return &group, nil
	}
	if err := rows.Err(); err != nil {
		return nil, errs.Wrap(err, "unable to read query results")
	}

	return nil, nil
}

func (d *Database) GetGroupById(ctx context.Context, tx *sql.Tx, groupId int64) (*record.Group, error) {

	groupStruct := sqlbuilder.NewStruct(new(record.Group)).
		For(d.Flavor)

	selectBuilder := groupStruct.SelectFrom(d.Flavor.Quote("groups"))
	selectBuilder.Where(selectBuilder.Equal("id", groupId))

	group, err := d.getGroupCommon(ctx, tx, selectBuilder, groupStruct)
	if err != nil {
		return nil, err
	}

	return group, nil
}

func (d *Database) GetGroupsByIds(ctx context.Context, tx *sql.Tx, groupIds []int64) ([]record.Group, error) {

	if len(groupIds) == 0 {
		return nil, nil
	}

	var groups []record.Group

	err := forEachIdBatch(groupIds, func(batch []int64) error {
		groupStruct := sqlbuilder.NewStruct(new(record.Group)).
			For(d.Flavor)

		selectBuilder := groupStruct.SelectFrom(d.Flavor.Quote("groups"))
		selectBuilder.Where(selectBuilder.In("id", sqlbuilder.Flatten(batch)...))

		sql, args := selectBuilder.Build()
		rows, err := d.QuerySQL(ctx, tx, sql, args...)
		if err != nil {
			return errs.Wrap(err, "unable to query database")
		}
		defer func() { _ = rows.Close() }()

		for rows.Next() {
			var group record.Group
			addr := groupStruct.Addr(&group)
			err = rows.Scan(addr...)
			if err != nil {
				return errs.Wrap(err, "unable to scan group")
			}
			groups = append(groups, group)
		}

		if err := rows.Err(); err != nil {
			return errs.Wrap(err, "unable to read query results")
		}

		return nil
	})
	if err != nil {
		return nil, err
	}

	return groups, nil
}

func (d *Database) GroupLoadPermissions(ctx context.Context, tx *sql.Tx, group *record.Group) error {

	if group == nil {
		return nil
	}

	groupPermissions, err := d.GetGroupPermissionsByGroupIds(ctx, tx, []int64{group.Id})
	if err != nil {
		return errs.Wrap(err, "unable to get group permissions")
	}

	permissionIds := make([]int64, len(groupPermissions))
	for i, groupPermission := range groupPermissions {
		permissionIds[i] = groupPermission.PermissionId
	}

	permissions, err := d.GetPermissionsByIds(ctx, tx, permissionIds)
	if err != nil {
		return errs.Wrap(err, "unable to get permissions")
	}

	group.Permissions = make([]record.Permission, len(permissions))
	copy(group.Permissions, permissions)

	return nil
}

func (d *Database) GroupsLoadPermissions(ctx context.Context, tx *sql.Tx, groups []record.Group) error {

	if groups == nil {
		return nil
	}

	groupIds := make([]int64, len(groups))
	for i, group := range groups {
		groupIds[i] = group.Id
	}

	groupPermissions, err := d.GetGroupPermissionsByGroupIds(ctx, tx, groupIds)
	if err != nil {
		return errs.Wrap(err, "unable to get group permissions")
	}

	permissionIds := make([]int64, len(groupPermissions))
	for i, groupPermission := range groupPermissions {
		permissionIds[i] = groupPermission.PermissionId
	}

	permissions, err := d.GetPermissionsByIds(ctx, tx, permissionIds)
	if err != nil {
		return errs.Wrap(err, "unable to get permissions")
	}

	permissionsMap := make(map[int64]record.Permission)
	for _, permission := range permissions {
		permissionsMap[permission.Id] = permission
	}

	groupPermissionsMap := make(map[int64][]record.GroupPermission)
	for _, groupPermission := range groupPermissions {
		groupPermissionsMap[groupPermission.GroupId] = append(groupPermissionsMap[groupPermission.GroupId], groupPermission)
	}

	for i, group := range groups {
		group.Permissions = make([]record.Permission, len(groupPermissionsMap[group.Id]))
		for j, groupPermission := range groupPermissionsMap[group.Id] {
			group.Permissions[j] = permissionsMap[groupPermission.PermissionId]
		}
		groups[i] = group
	}

	return nil
}

func (d *Database) GroupsLoadAttributes(ctx context.Context, tx *sql.Tx, groups []record.Group) error {

	if groups == nil {
		return nil
	}

	groupIds := make([]int64, len(groups))
	for i, group := range groups {
		groupIds[i] = group.Id
	}

	groupAttributes, err := d.GetGroupAttributesByGroupIds(ctx, tx, groupIds)
	if err != nil {
		return errs.Wrap(err, "unable to get group attributes")
	}

	groupAttributesMap := make(map[int64][]record.GroupAttribute)
	for _, groupAttribute := range groupAttributes {
		groupAttributesMap[groupAttribute.GroupId] = append(groupAttributesMap[groupAttribute.GroupId], groupAttribute)
	}

	for i, group := range groups {
		group.Attributes = groupAttributesMap[group.Id]
		groups[i] = group
	}

	return nil
}

func (d *Database) GetGroupByGroupIdentifier(ctx context.Context, tx *sql.Tx, groupIdentifier string) (*record.Group, error) {

	groupStruct := sqlbuilder.NewStruct(new(record.Group)).
		For(d.Flavor)

	selectBuilder := groupStruct.SelectFrom(d.Flavor.Quote("groups"))
	selectBuilder.Where(selectBuilder.Equal("group_identifier", groupIdentifier))

	group, err := d.getGroupCommon(ctx, tx, selectBuilder, groupStruct)
	if err != nil {
		return nil, err
	}
	// The engine may have folded a value this lookup did not ask for; see
	// engineFoldedTheMatch.
	if group != nil && engineFoldedTheMatch(group.GroupIdentifier, groupIdentifier) {
		return nil, nil
	}

	return group, nil
}

func (d *Database) GetAllGroups(ctx context.Context, tx *sql.Tx) ([]record.Group, error) {

	groupStruct := sqlbuilder.NewStruct(new(record.Group)).
		For(d.Flavor)

	selectBuilder := groupStruct.SelectFrom(d.Flavor.Quote("groups"))

	sql, args := selectBuilder.Build()
	rows, err := d.QuerySQL(ctx, tx, sql, args...)
	if err != nil {
		return nil, errs.Wrap(err, "unable to query database")
	}
	defer func() { _ = rows.Close() }()

	var groups []record.Group
	for rows.Next() {
		var group record.Group
		addr := groupStruct.Addr(&group)
		err = rows.Scan(addr...)
		if err != nil {
			return nil, errs.Wrap(err, "unable to scan group")
		}
		groups = append(groups, group)
	}

	if err := rows.Err(); err != nil {
		return nil, errs.Wrap(err, "unable to read query results")
	}

	return groups, nil
}

func (d *Database) GetAllGroupsPaginated(ctx context.Context, tx *sql.Tx, page int, pageSize int) ([]record.Group, int, error) {
	if page < 1 {
		page = 1
	}

	if pageSize < 1 {
		pageSize = 10
	}

	groupStruct := sqlbuilder.NewStruct(new(record.Group)).
		For(d.Flavor)

	selectBuilder := groupStruct.SelectFrom(d.Flavor.Quote("groups"))
	selectBuilder.OrderByAsc("group_identifier")
	selectBuilder.Offset(PageOffset(page, pageSize))
	selectBuilder.Limit(pageSize)

	sql, args := selectBuilder.Build()
	rows, err := d.QuerySQL(ctx, tx, sql, args...)
	if err != nil {
		return nil, 0, errs.Wrap(err, "unable to query database")
	}
	defer func() { _ = rows.Close() }()

	var groups []record.Group
	for rows.Next() {
		var group record.Group
		addr := groupStruct.Addr(&group)
		err = rows.Scan(addr...)
		if err != nil {
			return nil, 0, errs.Wrap(err, "unable to scan group")
		}
		groups = append(groups, group)
	}

	selectBuilder = d.Flavor.NewSelectBuilder()
	selectBuilder.Select("count(*)").From(d.Flavor.Quote("groups"))

	sql, args = selectBuilder.Build()
	rows2, err := d.QuerySQL(ctx, tx, sql, args...)
	if err != nil {
		return nil, 0, errs.Wrap(err, "unable to query database")
	}
	defer func() { _ = rows2.Close() }()

	var total int
	if rows2.Next() {
		err = rows2.Scan(&total)
		if err != nil {
			return nil, 0, errs.Wrap(err, "unable to scan count")
		}
	}

	if err := rows.Err(); err != nil {
		return nil, 0, errs.Wrap(err, "unable to read query results")
	}
	if err := rows2.Err(); err != nil {
		return nil, 0, errs.Wrap(err, "unable to read count results")
	}

	return groups, total, nil
}

func (d *Database) GetGroupMembersPaginated(ctx context.Context, tx *sql.Tx, groupId int64, page int, pageSize int) ([]record.User, int, error) {
	if groupId <= 0 {
		return nil, 0, errs.New("group id must be greater than 0")
	}

	if page < 1 {
		page = 1
	}

	if pageSize < 1 {
		pageSize = 10
	}

	userStruct := sqlbuilder.NewStruct(new(record.User)).
		For(d.Flavor)

	selectBuilder := userStruct.SelectFrom("users")
	selectBuilder.JoinWithOption(sqlbuilder.InnerJoin, "users_groups", "users.id = users_groups.user_id")
	selectBuilder.Where(selectBuilder.Equal("users_groups.group_id", groupId))
	// given_name does not order the rows totally, so paging over it alone can repeat a user on
	// the next page and skip another. See SearchUsersPaginated in user.go for the full reason (#112).
	selectBuilder.OrderByAsc("users.given_name").OrderByAsc("users.id")
	selectBuilder.Offset(PageOffset(page, pageSize))
	selectBuilder.Limit(pageSize)

	sql, args := selectBuilder.Build()
	rows, err := d.QuerySQL(ctx, tx, sql, args...)
	if err != nil {
		return nil, 0, errs.Wrap(err, "unable to query database")
	}
	defer func() { _ = rows.Close() }()

	var users []record.User
	for rows.Next() {
		var user record.User
		addr := userStruct.Addr(&user)
		err = rows.Scan(addr...)
		if err != nil {
			return nil, 0, errs.Wrap(err, "unable to scan user")
		}
		users = append(users, user)
	}

	selectBuilder = d.Flavor.NewSelectBuilder()
	selectBuilder.Select("count(*)").From("users")
	selectBuilder.JoinWithOption(sqlbuilder.InnerJoin, "users_groups", "users.id = users_groups.user_id")
	selectBuilder.Where(selectBuilder.Equal("users_groups.group_id", groupId))

	sql, args = selectBuilder.Build()
	rows2, err := d.QuerySQL(ctx, tx, sql, args...)
	if err != nil {
		return nil, 0, errs.Wrap(err, "unable to query database")
	}
	defer func() { _ = rows2.Close() }()

	var total int
	if rows2.Next() {
		err = rows2.Scan(&total)
		if err != nil {
			return nil, 0, errs.Wrap(err, "unable to scan count")
		}
	}

	if err := rows.Err(); err != nil {
		return nil, 0, errs.Wrap(err, "unable to read query results")
	}
	if err := rows2.Err(); err != nil {
		return nil, 0, errs.Wrap(err, "unable to read count results")
	}

	return users, total, nil
}

func (d *Database) CountGroupMembers(ctx context.Context, tx *sql.Tx, groupId int64) (int, error) {
	if groupId <= 0 {
		return 0, errs.New("group id must be greater than 0")
	}

	selectBuilder := d.Flavor.NewSelectBuilder()
	selectBuilder.Select("count(*)").From("users_groups")
	selectBuilder.Where(selectBuilder.Equal("group_id", groupId))

	sql, args := selectBuilder.Build()
	rows, err := d.QuerySQL(ctx, tx, sql, args...)
	if err != nil {
		return 0, errs.Wrap(err, "unable to query database")
	}
	defer func() { _ = rows.Close() }()

	var count int
	if rows.Next() {
		err = rows.Scan(&count)
		if err != nil {
			return 0, errs.Wrap(err, "unable to scan count")
		}
		return count, nil
	}
	if err := rows.Err(); err != nil {
		return 0, errs.Wrap(err, "unable to read query results")
	}

	return 0, nil
}

func (d *Database) DeleteGroup(ctx context.Context, tx *sql.Tx, groupId int64) error {

	clientStruct := sqlbuilder.NewStruct(new(record.Group)).
		For(d.Flavor)

	deleteBuilder := clientStruct.DeleteFrom(d.Flavor.Quote("groups"))
	deleteBuilder.Where(deleteBuilder.Equal("id", groupId))

	sql, args := deleteBuilder.Build()
	_, err := d.ExecSQL(ctx, tx, sql, args...)
	if err != nil {
		return errs.Wrap(err, "unable to delete group")
	}

	return nil
}
