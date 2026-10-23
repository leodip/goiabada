package commondb

import (
	"context"
	"database/sql"
	"time"

	"github.com/huandu/go-sqlbuilder"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/errs"
)

// groupColumns is the groups table as scanGroup reads it. The table's name is a reserved word,
// quoted in every statement naming it: with backticks on MySQL, double quotes on the other three.
var groupColumns = columnList{
	sqlite:   "id, created_at, updated_at, group_identifier, description, include_in_id_token, include_in_access_token",
	mysql:    "id, created_at, updated_at, group_identifier, description, include_in_id_token, include_in_access_token",
	postgres: "id, created_at, updated_at, group_identifier, description, include_in_id_token, include_in_access_token",
	mssql:    "id, created_at, updated_at, group_identifier, description, include_in_id_token, include_in_access_token",
}

// scanGroup reads one row selected with groupColumns.
func scanGroup(row rowScanner, group *record.Group) error {
	return row.Scan(
		&group.Id,
		&group.CreatedAt,
		&group.UpdatedAt,
		&group.GroupIdentifier,
		&group.Description,
		&group.IncludeInIdToken,
		&group.IncludeInAccessToken,
	)
}

var insertGroup = statement{
	sqlite: `INSERT INTO "groups" (created_at, updated_at, group_identifier, description, include_in_id_token, include_in_access_token) ` +
		`VALUES (?, ?, ?, ?, ?, ?)`,
	mysql: "INSERT INTO `groups` (created_at, updated_at, group_identifier, description, include_in_id_token, include_in_access_token) " +
		"VALUES (?, ?, ?, ?, ?, ?)",
	postgres: `INSERT INTO "groups" (created_at, updated_at, group_identifier, description, include_in_id_token, include_in_access_token) ` +
		`VALUES ($1, $2, $3, $4, $5, $6) RETURNING id`,
	mssql: `INSERT INTO "groups" (created_at, updated_at, group_identifier, description, include_in_id_token, include_in_access_token) ` +
		`OUTPUT INSERTED.id VALUES (@p1, @p2, @p3, @p4, @p5, @p6)`,
}

// updateGroup writes the whole row but created_at, which is dont-update.
var updateGroup = statement{
	sqlite: `UPDATE "groups" SET updated_at = ?, group_identifier = ?, description = ?, include_in_id_token = ?, ` +
		`include_in_access_token = ? WHERE id = ?`,
	mysql: "UPDATE `groups` SET updated_at = ?, group_identifier = ?, description = ?, include_in_id_token = ?, " +
		"include_in_access_token = ? WHERE id = ?",
	postgres: `UPDATE "groups" SET updated_at = $1, group_identifier = $2, description = $3, include_in_id_token = $4, ` +
		`include_in_access_token = $5 WHERE id = $6`,
	mssql: `UPDATE "groups" SET updated_at = @p1, group_identifier = @p2, description = @p3, include_in_id_token = @p4, ` +
		`include_in_access_token = @p5 WHERE id = @p6`,
}

var selectGroupById = statement{
	sqlite:   "SELECT " + groupColumns.sqlite + ` FROM "groups" WHERE id = ?`,
	mysql:    "SELECT " + groupColumns.mysql + " FROM `groups` WHERE id = ?",
	postgres: "SELECT " + groupColumns.postgres + ` FROM "groups" WHERE id = $1`,
	mssql:    "SELECT " + groupColumns.mssql + ` FROM "groups" WHERE id = @p1`,
}

var selectGroupByGroupIdentifier = statement{
	sqlite:   "SELECT " + groupColumns.sqlite + ` FROM "groups" WHERE group_identifier = ?`,
	mysql:    "SELECT " + groupColumns.mysql + " FROM `groups` WHERE group_identifier = ?",
	postgres: "SELECT " + groupColumns.postgres + ` FROM "groups" WHERE group_identifier = $1`,
	mssql:    "SELECT " + groupColumns.mssql + ` FROM "groups" WHERE group_identifier = @p1`,
}

// selectGroupsWhere is completed by an IN list of group ids.
var selectGroupsWhere = statement{
	sqlite:   "SELECT " + groupColumns.sqlite + ` FROM "groups" WHERE `,
	mysql:    "SELECT " + groupColumns.mysql + " FROM `groups` WHERE ",
	postgres: "SELECT " + groupColumns.postgres + ` FROM "groups" WHERE `,
	mssql:    "SELECT " + groupColumns.mssql + ` FROM "groups" WHERE `,
}

var selectAllGroups = statement{
	sqlite:   "SELECT " + groupColumns.sqlite + ` FROM "groups"`,
	mysql:    "SELECT " + groupColumns.mysql + " FROM `groups`",
	postgres: "SELECT " + groupColumns.postgres + ` FROM "groups"`,
	mssql:    "SELECT " + groupColumns.mssql + ` FROM "groups"`,
}

// selectGroupsPage binds the page size, then the offset. SQL Server pages with OFFSET … FETCH
// after its ORDER BY, naming the offset first, so its text numbers the two the other way round.
var selectGroupsPage = statement{
	sqlite:   "SELECT " + groupColumns.sqlite + ` FROM "groups" ORDER BY group_identifier ASC LIMIT ? OFFSET ?`,
	mysql:    "SELECT " + groupColumns.mysql + " FROM `groups` ORDER BY group_identifier ASC LIMIT ? OFFSET ?",
	postgres: "SELECT " + groupColumns.postgres + ` FROM "groups" ORDER BY group_identifier ASC LIMIT $1 OFFSET $2`,
	mssql: "SELECT " + groupColumns.mssql + ` FROM "groups" ORDER BY group_identifier ASC ` +
		`OFFSET @p2 ROWS FETCH NEXT @p1 ROWS ONLY`,
}

var countGroups = statement{
	sqlite:   `SELECT count(*) FROM "groups"`,
	mysql:    "SELECT count(*) FROM `groups`",
	postgres: `SELECT count(*) FROM "groups"`,
	mssql:    `SELECT count(*) FROM "groups"`,
}

var countGroupMembers = statement{
	sqlite:   "SELECT count(*) FROM users_groups WHERE group_id = ?",
	mysql:    "SELECT count(*) FROM users_groups WHERE group_id = ?",
	postgres: "SELECT count(*) FROM users_groups WHERE group_id = $1",
	mssql:    "SELECT count(*) FROM users_groups WHERE group_id = @p1",
}

var deleteGroup = statement{
	sqlite:   `DELETE FROM "groups" WHERE id = ?`,
	mysql:    "DELETE FROM `groups` WHERE id = ?",
	postgres: `DELETE FROM "groups" WHERE id = $1`,
	mssql:    `DELETE FROM "groups" WHERE id = @p1`,
}

func (d *Database) CreateGroup(ctx context.Context, tx *sql.Tx, group *record.Group) error {

	now := time.Now().UTC()

	originalCreatedAt := group.CreatedAt
	originalUpdatedAt := group.UpdatedAt
	group.CreatedAt = sql.NullTime{Time: now, Valid: true}
	group.UpdatedAt = sql.NullTime{Time: now, Valid: true}

	id, err := d.insert(ctx, tx, insertGroup, "group",
		group.CreatedAt, group.UpdatedAt, group.GroupIdentifier, group.Description, group.IncludeInIdToken,
		group.IncludeInAccessToken)
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

	_, err := d.ExecSQL(ctx, tx, updateGroup.text(d.Dialect),
		group.UpdatedAt, group.GroupIdentifier, group.Description, group.IncludeInIdToken, group.IncludeInAccessToken,
		group.Id)
	if err != nil {
		group.UpdatedAt = originalUpdatedAt
		return errs.Wrap(err, "unable to update group")
	}

	return nil
}

func (d *Database) GetGroupById(ctx context.Context, tx *sql.Tx, groupId int64) (*record.Group, error) {
	return queryOne(ctx, d, tx, selectGroupById.text(d.Dialect), []any{groupId}, scanGroup, "group")
}

func (d *Database) GetGroupsByIds(ctx context.Context, tx *sql.Tx, groupIds []int64) ([]record.Group, error) {

	if len(groupIds) == 0 {
		return nil, nil
	}

	var groups []record.Group

	err := forEachIdBatch(groupIds, func(batch []int64) error {
		query := selectGroupsWhere.text(d.Dialect) + inList(d.Dialect, "id", 1, len(batch))
		var err error
		groups, err = queryAll(ctx, d, tx, groups, query, int64Args(batch), scanGroup, "group")
		return err
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

	group, err := queryOne(ctx, d, tx, selectGroupByGroupIdentifier.text(d.Dialect), []any{groupIdentifier},
		scanGroup, "group")
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
	return queryAll(ctx, d, tx, nil, selectAllGroups.text(d.Dialect), nil, scanGroup, "group")
}

func (d *Database) GetAllGroupsPaginated(ctx context.Context, tx *sql.Tx, page int, pageSize int) ([]record.Group, int, error) {
	if page < 1 {
		page = 1
	}

	if pageSize < 1 {
		pageSize = 10
	}

	groups, err := queryAll(ctx, d, tx, nil, selectGroupsPage.text(d.Dialect),
		[]any{pageSize, PageOffset(page, pageSize)}, scanGroup, "group")
	if err != nil {
		return nil, 0, err
	}

	rows, err := d.QuerySQL(ctx, tx, countGroups.text(d.Dialect))
	if err != nil {
		return nil, 0, errs.Wrap(err, "unable to query database")
	}
	defer func() { _ = rows.Close() }()

	var total int
	if rows.Next() {
		err = rows.Scan(&total)
		if err != nil {
			return nil, 0, errs.Wrap(err, "unable to scan count")
		}
	}
	if err := rows.Err(); err != nil {
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

	rows, err := d.QuerySQL(ctx, tx, countGroupMembers.text(d.Dialect), groupId)
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

	_, err := d.ExecSQL(ctx, tx, deleteGroup.text(d.Dialect), groupId)
	if err != nil {
		return errs.Wrap(err, "unable to delete group")
	}

	return nil
}
