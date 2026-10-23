package commondb

import (
	"context"
	"database/sql"
	"time"

	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/errs"
)

// userPermissionColumns is the users_permissions table as scanUserPermission reads it.
var userPermissionColumns = columnList{
	sqlite:   "id, created_at, updated_at, user_id, permission_id",
	mysql:    "id, created_at, updated_at, user_id, permission_id",
	postgres: "id, created_at, updated_at, user_id, permission_id",
	mssql:    "id, created_at, updated_at, user_id, permission_id",
}

// scanUserPermission reads one row selected with userPermissionColumns.
func scanUserPermission(row rowScanner, userPermission *record.UserPermission) error {
	return row.Scan(
		&userPermission.Id,
		&userPermission.CreatedAt,
		&userPermission.UpdatedAt,
		&userPermission.UserId,
		&userPermission.PermissionId,
	)
}

var insertUserPermission = statement{
	sqlite:   "INSERT INTO users_permissions (created_at, updated_at, user_id, permission_id) VALUES (?, ?, ?, ?)",
	mysql:    "INSERT INTO users_permissions (created_at, updated_at, user_id, permission_id) VALUES (?, ?, ?, ?)",
	postgres: "INSERT INTO users_permissions (created_at, updated_at, user_id, permission_id) VALUES ($1, $2, $3, $4) RETURNING id",
	mssql:    "INSERT INTO users_permissions (created_at, updated_at, user_id, permission_id) OUTPUT INSERTED.id VALUES (@p1, @p2, @p3, @p4)",
}

// updateUserPermission writes the whole row but created_at, which is dont-update.
var updateUserPermission = statement{
	sqlite:   "UPDATE users_permissions SET updated_at = ?, user_id = ?, permission_id = ? WHERE id = ?",
	mysql:    "UPDATE users_permissions SET updated_at = ?, user_id = ?, permission_id = ? WHERE id = ?",
	postgres: "UPDATE users_permissions SET updated_at = $1, user_id = $2, permission_id = $3 WHERE id = $4",
	mssql:    "UPDATE users_permissions SET updated_at = @p1, user_id = @p2, permission_id = @p3 WHERE id = @p4",
}

var selectUserPermissionById = statement{
	sqlite:   "SELECT " + userPermissionColumns.sqlite + " FROM users_permissions WHERE id = ?",
	mysql:    "SELECT " + userPermissionColumns.mysql + " FROM users_permissions WHERE id = ?",
	postgres: "SELECT " + userPermissionColumns.postgres + " FROM users_permissions WHERE id = $1",
	mssql:    "SELECT " + userPermissionColumns.mssql + " FROM users_permissions WHERE id = @p1",
}

var selectUserPermissionByUserIdAndPermissionId = statement{
	sqlite:   "SELECT " + userPermissionColumns.sqlite + " FROM users_permissions WHERE user_id = ? AND permission_id = ?",
	mysql:    "SELECT " + userPermissionColumns.mysql + " FROM users_permissions WHERE user_id = ? AND permission_id = ?",
	postgres: "SELECT " + userPermissionColumns.postgres + " FROM users_permissions WHERE user_id = $1 AND permission_id = $2",
	mssql:    "SELECT " + userPermissionColumns.mssql + " FROM users_permissions WHERE user_id = @p1 AND permission_id = @p2",
}

var selectUserPermissionsByUserId = statement{
	sqlite:   "SELECT " + userPermissionColumns.sqlite + " FROM users_permissions WHERE user_id = ?",
	mysql:    "SELECT " + userPermissionColumns.mysql + " FROM users_permissions WHERE user_id = ?",
	postgres: "SELECT " + userPermissionColumns.postgres + " FROM users_permissions WHERE user_id = $1",
	mssql:    "SELECT " + userPermissionColumns.mssql + " FROM users_permissions WHERE user_id = @p1",
}

// selectUserPermissionsWhere is completed by an IN list of user ids.
var selectUserPermissionsWhere = statement{
	sqlite:   "SELECT " + userPermissionColumns.sqlite + " FROM users_permissions WHERE ",
	mysql:    "SELECT " + userPermissionColumns.mysql + " FROM users_permissions WHERE ",
	postgres: "SELECT " + userPermissionColumns.postgres + " FROM users_permissions WHERE ",
	mssql:    "SELECT " + userPermissionColumns.mssql + " FROM users_permissions WHERE ",
}

// selectUsersByPermissionIdPage is the users holding one permission directly, a page at a time: the
// permission id, then the page size, then the offset, which SQL Server's OFFSET … FETCH names before
// the page size. given_name does not order the rows totally, so paging over it alone can repeat a
// user on the next page and skip another; see selectUsersPage in user.go for the full reason (#112).
var selectUsersByPermissionIdPage = statement{
	sqlite: "SELECT " + userColumns.sqlite + " FROM users INNER JOIN users_permissions ON users.id = users_permissions.user_id " +
		"WHERE users_permissions.permission_id = ? ORDER BY users.given_name ASC, users.id ASC LIMIT ? OFFSET ?",
	mysql: "SELECT " + userColumns.mysql + " FROM users INNER JOIN users_permissions ON users.id = users_permissions.user_id " +
		"WHERE users_permissions.permission_id = ? ORDER BY users.given_name ASC, users.id ASC LIMIT ? OFFSET ?",
	postgres: "SELECT " + userColumns.postgres + " FROM users INNER JOIN users_permissions ON users.id = users_permissions.user_id " +
		"WHERE users_permissions.permission_id = $1 ORDER BY users.given_name ASC, users.id ASC LIMIT $2 OFFSET $3",
	mssql: "SELECT " + userColumns.mssql + " FROM users INNER JOIN users_permissions ON users.id = users_permissions.user_id " +
		"WHERE users_permissions.permission_id = @p1 ORDER BY users.given_name ASC, users.id ASC " +
		"OFFSET @p3 ROWS FETCH NEXT @p2 ROWS ONLY",
}

// countUsersByPermissionId counts the rows selectUsersByPermissionIdPage pages through, over the
// same join.
var countUsersByPermissionId = statement{
	sqlite: "SELECT count(*) FROM users INNER JOIN users_permissions ON users.id = users_permissions.user_id " +
		"WHERE users_permissions.permission_id = ?",
	mysql: "SELECT count(*) FROM users INNER JOIN users_permissions ON users.id = users_permissions.user_id " +
		"WHERE users_permissions.permission_id = ?",
	postgres: "SELECT count(*) FROM users INNER JOIN users_permissions ON users.id = users_permissions.user_id " +
		"WHERE users_permissions.permission_id = $1",
	mssql: "SELECT count(*) FROM users INNER JOIN users_permissions ON users.id = users_permissions.user_id " +
		"WHERE users_permissions.permission_id = @p1",
}

var deleteUserPermission = statement{
	sqlite:   "DELETE FROM users_permissions WHERE id = ?",
	mysql:    "DELETE FROM users_permissions WHERE id = ?",
	postgres: "DELETE FROM users_permissions WHERE id = $1",
	mssql:    "DELETE FROM users_permissions WHERE id = @p1",
}

// countEnabledUsersHoldingPermission binds whether the user is enabled, then the permission id
// once for each route: held directly, then held through a group.
var countEnabledUsersHoldingPermission = statement{
	sqlite: "SELECT count(*) FROM users WHERE users.enabled = ? AND (" +
		"EXISTS (SELECT 1 FROM users_permissions WHERE users_permissions.user_id = users.id AND users_permissions.permission_id = ?) OR " +
		"EXISTS (SELECT 1 FROM users_groups INNER JOIN groups_permissions ON groups_permissions.group_id = users_groups.group_id " +
		"WHERE users_groups.user_id = users.id AND groups_permissions.permission_id = ?))",
	mysql: "SELECT count(*) FROM users WHERE users.enabled = ? AND (" +
		"EXISTS (SELECT 1 FROM users_permissions WHERE users_permissions.user_id = users.id AND users_permissions.permission_id = ?) OR " +
		"EXISTS (SELECT 1 FROM users_groups INNER JOIN groups_permissions ON groups_permissions.group_id = users_groups.group_id " +
		"WHERE users_groups.user_id = users.id AND groups_permissions.permission_id = ?))",
	postgres: "SELECT count(*) FROM users WHERE users.enabled = $1 AND (" +
		"EXISTS (SELECT 1 FROM users_permissions WHERE users_permissions.user_id = users.id AND users_permissions.permission_id = $2) OR " +
		"EXISTS (SELECT 1 FROM users_groups INNER JOIN groups_permissions ON groups_permissions.group_id = users_groups.group_id " +
		"WHERE users_groups.user_id = users.id AND groups_permissions.permission_id = $3))",
	mssql: "SELECT count(*) FROM users WHERE users.enabled = @p1 AND (" +
		"EXISTS (SELECT 1 FROM users_permissions WHERE users_permissions.user_id = users.id AND users_permissions.permission_id = @p2) OR " +
		"EXISTS (SELECT 1 FROM users_groups INNER JOIN groups_permissions ON groups_permissions.group_id = users_groups.group_id " +
		"WHERE users_groups.user_id = users.id AND groups_permissions.permission_id = @p3))",
}

func (d *Database) CreateUserPermission(ctx context.Context, tx *sql.Tx, userPermission *record.UserPermission) error {

	if userPermission.UserId == 0 {
		return errs.New("can't create userPermission with user_id 0")
	}

	if userPermission.PermissionId == 0 {
		return errs.New("can't create userPermission with permission_id 0")
	}

	now := time.Now().UTC()

	originalCreatedAt := userPermission.CreatedAt
	originalUpdatedAt := userPermission.UpdatedAt
	userPermission.CreatedAt = sql.NullTime{Time: now, Valid: true}
	userPermission.UpdatedAt = sql.NullTime{Time: now, Valid: true}

	id, err := d.insert(ctx, tx, insertUserPermission, "userPermission",
		userPermission.CreatedAt, userPermission.UpdatedAt, userPermission.UserId, userPermission.PermissionId)
	if err != nil {
		userPermission.CreatedAt = originalCreatedAt
		userPermission.UpdatedAt = originalUpdatedAt
		return err
	}

	userPermission.Id = id
	return nil
}

func (d *Database) UpdateUserPermission(ctx context.Context, tx *sql.Tx, userPermission *record.UserPermission) error {

	if userPermission.Id == 0 {
		return errs.New("can't update userPermission with id 0")
	}

	originalUpdatedAt := userPermission.UpdatedAt
	userPermission.UpdatedAt = sql.NullTime{Time: time.Now().UTC(), Valid: true}

	_, err := d.ExecSQL(ctx, tx, updateUserPermission.text(d.Dialect),
		userPermission.UpdatedAt, userPermission.UserId, userPermission.PermissionId,
		userPermission.Id)
	if err != nil {
		userPermission.UpdatedAt = originalUpdatedAt
		return errs.Wrap(err, "unable to update userPermission")
	}

	return nil
}

func (d *Database) GetUserPermissionById(ctx context.Context, tx *sql.Tx, userPermissionId int64) (*record.UserPermission, error) {
	return queryOne(ctx, d, tx, selectUserPermissionById.text(d.Dialect), []any{userPermissionId},
		scanUserPermission, "userPermission")
}

func (d *Database) GetUserPermissionsByUserIds(ctx context.Context, tx *sql.Tx, userIds []int64) ([]record.UserPermission, error) {

	if len(userIds) == 0 {
		return nil, nil
	}

	var userPermissions []record.UserPermission

	err := forEachIdBatch(userIds, func(batch []int64) error {
		query := selectUserPermissionsWhere.text(d.Dialect) + inList(d.Dialect, "user_id", 1, len(batch))
		var err error
		userPermissions, err = queryAll(ctx, d, tx, userPermissions, query, int64Args(batch),
			scanUserPermission, "userPermission")
		return err
	})
	if err != nil {
		return nil, err
	}

	return userPermissions, nil
}

func (d *Database) GetUserPermissionsByUserId(ctx context.Context, tx *sql.Tx, userId int64) ([]record.UserPermission, error) {
	return queryAll(ctx, d, tx, nil, selectUserPermissionsByUserId.text(d.Dialect), []any{userId},
		scanUserPermission, "userPermission")
}

func (d *Database) GetUserPermissionByUserIdAndPermissionId(ctx context.Context, tx *sql.Tx, userId, permissionId int64) (*record.UserPermission, error) {
	return queryOne(ctx, d, tx, selectUserPermissionByUserIdAndPermissionId.text(d.Dialect),
		[]any{userId, permissionId}, scanUserPermission, "userPermission")
}

func (d *Database) GetUsersByPermissionIdPaginated(ctx context.Context, tx *sql.Tx, permissionId int64, page int, pageSize int) ([]record.User, int, error) {

	if permissionId <= 0 {
		return nil, 0, errs.New("permissionId must be greater than 0")
	}

	if page < 1 {
		page = 1
	}

	if pageSize < 1 {
		pageSize = 10
	}

	users, err := queryAll(ctx, d, tx, nil, selectUsersByPermissionIdPage.text(d.Dialect),
		[]any{permissionId, pageSize, PageOffset(page, pageSize)}, scanUser, "user")
	if err != nil {
		return nil, 0, err
	}

	rows, err := d.QuerySQL(ctx, tx, countUsersByPermissionId.text(d.Dialect), permissionId)
	if err != nil {
		return nil, 0, errs.Wrap(err, "unable to query database")
	}
	defer func() { _ = rows.Close() }()

	var total int
	if rows.Next() {
		err = rows.Scan(&total)
		if err != nil {
			return nil, 0, errs.Wrap(err, "unable to scan total")
		}
	}
	if err := rows.Err(); err != nil {
		return nil, 0, errs.Wrap(err, "unable to read count results")
	}

	return users, total, nil
}

func (d *Database) DeleteUserPermission(ctx context.Context, tx *sql.Tx, userPermissionId int64) error {

	_, err := d.ExecSQL(ctx, tx, deleteUserPermission.text(d.Dialect), userPermissionId)
	if err != nil {
		return errs.Wrap(err, "unable to delete userPermission")
	}

	return nil
}

// CountEnabledUsersHoldingPermission counts the enabled users holding the permission, directly or
// through any of their groups. Each is counted once however many ways they hold it, since the two
// routes are EXISTS tests on the user rather than joins that would repeat a user per grant. It is
// what the last-administrator guard counts (#402 decision 10).
func (d *Database) CountEnabledUsersHoldingPermission(ctx context.Context, tx *sql.Tx, permissionId int64) (int, error) {
	if permissionId <= 0 {
		return 0, errs.New("permission id must be greater than 0")
	}

	rows, err := d.QuerySQL(ctx, tx, countEnabledUsersHoldingPermission.text(d.Dialect),
		true, permissionId, permissionId)
	if err != nil {
		return 0, errs.Wrap(err, "unable to count the enabled users holding the permission")
	}
	defer func() { _ = rows.Close() }()

	var holders int
	if rows.Next() {
		if err := rows.Scan(&holders); err != nil {
			return 0, errs.Wrap(err, "unable to scan the count of the enabled users holding the permission")
		}
	}
	if err := rows.Err(); err != nil {
		return 0, errs.Wrap(err, "unable to read query results")
	}

	return holders, nil
}
