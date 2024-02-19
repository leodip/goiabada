package commondb

import (
	"database/sql"
	"time"

	"github.com/huandu/go-sqlbuilder"
	"github.com/leodip/goiabada/internal/entitiesv2"
	"github.com/pkg/errors"
)

func (d *CommonDatabase) CreateGroup(tx *sql.Tx, group *entitiesv2.Group) error {

	now := time.Now().UTC()

	originalCreatedAt := group.CreatedAt
	originalUpdatedAt := group.UpdatedAt
	group.CreatedAt = sql.NullTime{Time: now, Valid: true}
	group.UpdatedAt = sql.NullTime{Time: now, Valid: true}

	groupStruct := sqlbuilder.NewStruct(new(entitiesv2.Group)).
		For(d.Flavor)

	insertBuilder := groupStruct.WithoutTag("pk").InsertInto("`groups`", group)

	sql, args := insertBuilder.Build()
	result, err := d.ExecSql(tx, sql, args...)
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

func (d *CommonDatabase) UpdateGroup(tx *sql.Tx, group *entitiesv2.Group) error {

	if group.Id == 0 {
		return errors.New("can't update group with id 0")
	}

	originalUpdatedAt := group.UpdatedAt
	group.UpdatedAt = sql.NullTime{Time: time.Now().UTC(), Valid: true}

	groupStruct := sqlbuilder.NewStruct(new(entitiesv2.Group)).
		For(d.Flavor)

	updateBuilder := groupStruct.WithoutTag("pk").Update("`groups`", group)
	updateBuilder.Where(updateBuilder.Equal("id", group.Id))

	sql, args := updateBuilder.Build()
	_, err := d.ExecSql(tx, sql, args...)
	if err != nil {
		group.UpdatedAt = originalUpdatedAt
		return errors.Wrap(err, "unable to update group")
	}

	return nil
}

func (d *CommonDatabase) getGroupCommon(tx *sql.Tx, selectBuilder *sqlbuilder.SelectBuilder,
	groupStruct *sqlbuilder.Struct) (*entitiesv2.Group, error) {

	sql, args := selectBuilder.Build()
	rows, err := d.QuerySql(tx, sql, args...)
	if err != nil {
		return nil, errors.Wrap(err, "unable to query database")
	}
	defer rows.Close()

	var group entitiesv2.Group
	if rows.Next() {
		addr := groupStruct.Addr(&group)
		err = rows.Scan(addr...)
		if err != nil {
			return nil, errors.Wrap(err, "unable to scan group")
		}
		return &group, nil
	}
	return nil, nil
}

func (d *CommonDatabase) GetGroupById(tx *sql.Tx, groupId int64) (*entitiesv2.Group, error) {

	groupStruct := sqlbuilder.NewStruct(new(entitiesv2.Group)).
		For(d.Flavor)

	selectBuilder := groupStruct.SelectFrom("`groups`")
	selectBuilder.Where(selectBuilder.Equal("id", groupId))

	group, err := d.getGroupCommon(tx, selectBuilder, groupStruct)
	if err != nil {
		return nil, err
	}

	return group, nil
}

func (d *CommonDatabase) GetGroupsByIds(tx *sql.Tx, groupIds []int64) ([]entitiesv2.Group, error) {

	if len(groupIds) == 0 {
		return nil, nil
	}

	groupStruct := sqlbuilder.NewStruct(new(entitiesv2.Group)).
		For(d.Flavor)

	selectBuilder := groupStruct.SelectFrom("`groups`")
	selectBuilder.Where(selectBuilder.In("id", sqlbuilder.Flatten(groupIds)...))

	sql, args := selectBuilder.Build()
	rows, err := d.QuerySql(tx, sql, args...)
	if err != nil {
		return nil, errors.Wrap(err, "unable to query database")
	}
	defer rows.Close()

	var groups []entitiesv2.Group
	for rows.Next() {
		var group entitiesv2.Group
		addr := groupStruct.Addr(&group)
		err = rows.Scan(addr...)
		if err != nil {
			return nil, errors.Wrap(err, "unable to scan group")
		}
		groups = append(groups, group)
	}

	return groups, nil
}

func (d *CommonDatabase) GroupLoadPermissions(tx *sql.Tx, group *entitiesv2.Group) error {

	if group == nil {
		return nil
	}

	groupPermissions, err := d.GetGroupPermissionsByGroupIds(tx, []int64{group.Id})
	if err != nil {
		return errors.Wrap(err, "unable to get group permissions")
	}

	permissionIds := make([]int64, len(groupPermissions))
	for i, groupPermission := range groupPermissions {
		permissionIds[i] = groupPermission.PermissionId
	}

	permissions, err := d.GetPermissionsByIds(tx, permissionIds)
	if err != nil {
		return errors.Wrap(err, "unable to get permissions")
	}

	group.Permissions = make([]entitiesv2.Permission, len(permissions))
	copy(group.Permissions, permissions)

	return nil
}

func (d *CommonDatabase) GroupsLoadPermissions(tx *sql.Tx, groups []entitiesv2.Group) error {

	if groups == nil {
		return nil
	}

	groupIds := make([]int64, len(groups))
	for i, group := range groups {
		groupIds[i] = group.Id
	}

	groupPermissions, err := d.GetGroupPermissionsByGroupIds(tx, groupIds)
	if err != nil {
		return errors.Wrap(err, "unable to get group permissions")
	}

	permissionIds := make([]int64, len(groupPermissions))
	for i, groupPermission := range groupPermissions {
		permissionIds[i] = groupPermission.PermissionId
	}

	permissions, err := d.GetPermissionsByIds(tx, permissionIds)
	if err != nil {
		return errors.Wrap(err, "unable to get permissions")
	}

	permissionsMap := make(map[int64]entitiesv2.Permission)
	for _, permission := range permissions {
		permissionsMap[permission.Id] = permission
	}

	groupPermissionsMap := make(map[int64][]entitiesv2.GroupPermission)
	for _, groupPermission := range groupPermissions {
		groupPermissionsMap[groupPermission.GroupId] = append(groupPermissionsMap[groupPermission.GroupId], groupPermission)
	}

	for i, group := range groups {
		group.Permissions = make([]entitiesv2.Permission, len(groupPermissionsMap[group.Id]))
		for j, groupPermission := range groupPermissionsMap[group.Id] {
			group.Permissions[j] = permissionsMap[groupPermission.PermissionId]
		}
		groups[i] = group
	}

	return nil
}

func (d *CommonDatabase) GroupsLoadAttributes(tx *sql.Tx, groups []entitiesv2.Group) error {

	if groups == nil {
		return nil
	}

	groupIds := make([]int64, len(groups))
	for i, group := range groups {
		groupIds[i] = group.Id
	}

	groupAttributes, err := d.GetGroupAttributesByGroupIds(tx, groupIds)
	if err != nil {
		return errors.Wrap(err, "unable to get group attributes")
	}

	groupAttributesMap := make(map[int64][]entitiesv2.GroupAttribute)
	for _, groupAttribute := range groupAttributes {
		groupAttributesMap[groupAttribute.GroupId] = append(groupAttributesMap[groupAttribute.GroupId], groupAttribute)
	}

	for i, group := range groups {
		group.Attributes = groupAttributesMap[group.Id]
		groups[i] = group
	}

	return nil
}

func (d *CommonDatabase) GetGroupByGroupIdentifier(tx *sql.Tx, groupIdentifier string) (*entitiesv2.Group, error) {

	groupStruct := sqlbuilder.NewStruct(new(entitiesv2.Group)).
		For(d.Flavor)

	selectBuilder := groupStruct.SelectFrom("`groups`")
	selectBuilder.Where(selectBuilder.Equal("group_identifier", groupIdentifier))

	group, err := d.getGroupCommon(tx, selectBuilder, groupStruct)
	if err != nil {
		return nil, err
	}

	return group, nil
}

func (d *CommonDatabase) GetAllGroups(tx *sql.Tx) ([]*entitiesv2.Group, error) {

	groupStruct := sqlbuilder.NewStruct(new(entitiesv2.Group)).
		For(d.Flavor)

	selectBuilder := groupStruct.SelectFrom("`groups`")

	sql, args := selectBuilder.Build()
	rows, err := d.QuerySql(tx, sql, args...)
	if err != nil {
		return nil, errors.Wrap(err, "unable to query database")
	}
	defer rows.Close()

	var groups []*entitiesv2.Group
	for rows.Next() {
		var group entitiesv2.Group
		addr := groupStruct.Addr(&group)
		err = rows.Scan(addr...)
		if err != nil {
			return nil, errors.Wrap(err, "unable to scan group")
		}
		groups = append(groups, &group)
	}

	return groups, nil
}

func (d *CommonDatabase) GetAllGroupsPaginated(tx *sql.Tx, page int, pageSize int) ([]entitiesv2.Group, int, error) {
	if page < 1 {
		page = 1
	}

	if pageSize < 1 {
		pageSize = 10
	}

	groupStruct := sqlbuilder.NewStruct(new(entitiesv2.Group)).
		For(d.Flavor)

	selectBuilder := groupStruct.SelectFrom("`groups`")
	selectBuilder.OrderBy("group_identifier").Asc()
	selectBuilder.Offset((page - 1) * pageSize)
	selectBuilder.Limit(pageSize)

	sql, args := selectBuilder.Build()
	rows, err := d.QuerySql(tx, sql, args...)
	if err != nil {
		return nil, 0, errors.Wrap(err, "unable to query database")
	}
	defer rows.Close()

	var groups []entitiesv2.Group
	for rows.Next() {
		var group entitiesv2.Group
		addr := groupStruct.Addr(&group)
		err = rows.Scan(addr...)
		if err != nil {
			return nil, 0, errors.Wrap(err, "unable to scan group")
		}
		groups = append(groups, group)
	}

	selectBuilder = d.Flavor.NewSelectBuilder()
	selectBuilder.Select("count(*)").From("`groups`")

	sql, args = selectBuilder.Build()
	rows, err = d.QuerySql(tx, sql, args...)
	if err != nil {
		return nil, 0, errors.Wrap(err, "unable to query database")
	}
	defer rows.Close()

	var total int
	if rows.Next() {
		rows.Scan(&total)
	}

	return groups, total, nil
}

func (d *CommonDatabase) GetGroupMembersPaginated(tx *sql.Tx, groupId int64, page int, pageSize int) ([]entitiesv2.User, int, error) {
	if groupId <= 0 {
		return nil, 0, errors.New("group id must be greater than 0")
	}

	if page < 1 {
		page = 1
	}

	if pageSize < 1 {
		pageSize = 10
	}

	userStruct := sqlbuilder.NewStruct(new(entitiesv2.User)).
		For(d.Flavor)

	selectBuilder := userStruct.SelectFrom("users")
	selectBuilder.JoinWithOption(sqlbuilder.InnerJoin, "users_groups", "users.id = users_groups.user_id")
	selectBuilder.Where(selectBuilder.Equal("users_groups.group_id", groupId))
	selectBuilder.OrderBy("users.given_name").Asc()
	selectBuilder.Offset((page - 1) * pageSize)
	selectBuilder.Limit(pageSize)

	sql, args := selectBuilder.Build()
	rows, err := d.QuerySql(nil, sql, args...)
	if err != nil {
		return nil, 0, errors.Wrap(err, "unable to query database")
	}
	defer rows.Close()

	var users []entitiesv2.User
	for rows.Next() {
		var user entitiesv2.User
		addr := userStruct.Addr(&user)
		err = rows.Scan(addr...)
		if err != nil {
			return nil, 0, errors.Wrap(err, "unable to scan user")
		}
		users = append(users, user)
	}

	selectBuilder = d.Flavor.NewSelectBuilder()
	selectBuilder.Select("count(*)").From("users")
	selectBuilder.JoinWithOption(sqlbuilder.InnerJoin, "users_groups", "users.id = users_groups.user_id")
	selectBuilder.Where(selectBuilder.Equal("users_groups.group_id", groupId))

	sql, args = selectBuilder.Build()
	rows, err = d.QuerySql(nil, sql, args...)
	if err != nil {
		return nil, 0, errors.Wrap(err, "unable to query database")
	}
	defer rows.Close()

	var total int
	if rows.Next() {
		rows.Scan(&total)
	}

	return users, total, nil
}

func (d *CommonDatabase) CountGroupMembers(tx *sql.Tx, groupId int64) (int, error) {
	if groupId <= 0 {
		return 0, errors.New("group id must be greater than 0")
	}

	selectBuilder := d.Flavor.NewSelectBuilder()
	selectBuilder.Select("count(*)").From("users_groups")
	selectBuilder.Where(selectBuilder.Equal("group_id", groupId))

	sql, args := selectBuilder.Build()
	rows, err := d.QuerySql(tx, sql, args...)
	if err != nil {
		return 0, errors.Wrap(err, "unable to query database")
	}
	defer rows.Close()

	var count int
	if rows.Next() {
		err = rows.Scan(&count)
		if err != nil {
			return 0, errors.Wrap(err, "unable to scan count")
		}
		return count, nil
	}
	return 0, nil
}

func (d *CommonDatabase) DeleteGroup(tx *sql.Tx, groupId int64) error {

	clientStruct := sqlbuilder.NewStruct(new(entitiesv2.Group)).
		For(d.Flavor)

	deleteBuilder := clientStruct.DeleteFrom("`groups`")
	deleteBuilder.Where(deleteBuilder.Equal("id", groupId))

	sql, args := deleteBuilder.Build()
	_, err := d.ExecSql(tx, sql, args...)
	if err != nil {
		return errors.Wrap(err, "unable to delete group")
	}

	return nil
}
