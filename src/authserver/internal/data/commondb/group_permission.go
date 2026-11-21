package commondb

import (
	"context"
	"database/sql"
	"time"

	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/errs"
)

// groupPermissionColumns is the groups_permissions table as scanGroupPermission reads it.
var groupPermissionColumns = columnList{
	sqlite:   "id, created_at, updated_at, group_id, permission_id",
	mysql:    "id, created_at, updated_at, group_id, permission_id",
	postgres: "id, created_at, updated_at, group_id, permission_id",
	mssql:    "id, created_at, updated_at, group_id, permission_id",
}

// scanGroupPermission reads one row selected with groupPermissionColumns.
func scanGroupPermission(row rowScanner, groupPermission *record.GroupPermission) error {
	return row.Scan(
		&groupPermission.ID,
		&groupPermission.CreatedAt,
		&groupPermission.UpdatedAt,
		&groupPermission.GroupID,
		&groupPermission.PermissionID,
	)
}

var insertGroupPermission = statement{
	sqlite:   "INSERT INTO groups_permissions (created_at, updated_at, group_id, permission_id) VALUES (?, ?, ?, ?)",
	mysql:    "INSERT INTO groups_permissions (created_at, updated_at, group_id, permission_id) VALUES (?, ?, ?, ?)",
	postgres: "INSERT INTO groups_permissions (created_at, updated_at, group_id, permission_id) VALUES ($1, $2, $3, $4) RETURNING id",
	mssql:    "INSERT INTO groups_permissions (created_at, updated_at, group_id, permission_id) OUTPUT INSERTED.id VALUES (@p1, @p2, @p3, @p4)",
}

// updateGroupPermission writes the whole row but created_at, which is dont-update.
var updateGroupPermission = statement{
	sqlite:   "UPDATE groups_permissions SET updated_at = ?, group_id = ?, permission_id = ? WHERE id = ?",
	mysql:    "UPDATE groups_permissions SET updated_at = ?, group_id = ?, permission_id = ? WHERE id = ?",
	postgres: "UPDATE groups_permissions SET updated_at = $1, group_id = $2, permission_id = $3 WHERE id = $4",
	mssql:    "UPDATE groups_permissions SET updated_at = @p1, group_id = @p2, permission_id = @p3 WHERE id = @p4",
}

var selectGroupPermissionByID = statement{
	sqlite:   "SELECT " + groupPermissionColumns.sqlite + " FROM groups_permissions WHERE id = ?",
	mysql:    "SELECT " + groupPermissionColumns.mysql + " FROM groups_permissions WHERE id = ?",
	postgres: "SELECT " + groupPermissionColumns.postgres + " FROM groups_permissions WHERE id = $1",
	mssql:    "SELECT " + groupPermissionColumns.mssql + " FROM groups_permissions WHERE id = @p1",
}

var selectGroupPermissionByGroupIDAndPermissionID = statement{
	sqlite:   "SELECT " + groupPermissionColumns.sqlite + " FROM groups_permissions WHERE group_id = ? AND permission_id = ?",
	mysql:    "SELECT " + groupPermissionColumns.mysql + " FROM groups_permissions WHERE group_id = ? AND permission_id = ?",
	postgres: "SELECT " + groupPermissionColumns.postgres + " FROM groups_permissions WHERE group_id = $1 AND permission_id = $2",
	mssql:    "SELECT " + groupPermissionColumns.mssql + " FROM groups_permissions WHERE group_id = @p1 AND permission_id = @p2",
}

var selectGroupPermissionsByGroupID = statement{
	sqlite:   "SELECT " + groupPermissionColumns.sqlite + " FROM groups_permissions WHERE group_id = ?",
	mysql:    "SELECT " + groupPermissionColumns.mysql + " FROM groups_permissions WHERE group_id = ?",
	postgres: "SELECT " + groupPermissionColumns.postgres + " FROM groups_permissions WHERE group_id = $1",
	mssql:    "SELECT " + groupPermissionColumns.mssql + " FROM groups_permissions WHERE group_id = @p1",
}

// selectGroupPermissionsWhere is completed by an IN list of group ids.
var selectGroupPermissionsWhere = statement{
	sqlite:   "SELECT " + groupPermissionColumns.sqlite + " FROM groups_permissions WHERE ",
	mysql:    "SELECT " + groupPermissionColumns.mysql + " FROM groups_permissions WHERE ",
	postgres: "SELECT " + groupPermissionColumns.postgres + " FROM groups_permissions WHERE ",
	mssql:    "SELECT " + groupPermissionColumns.mssql + " FROM groups_permissions WHERE ",
}

var deleteGroupPermission = statement{
	sqlite:   "DELETE FROM groups_permissions WHERE id = ?",
	mysql:    "DELETE FROM groups_permissions WHERE id = ?",
	postgres: "DELETE FROM groups_permissions WHERE id = $1",
	mssql:    "DELETE FROM groups_permissions WHERE id = @p1",
}

func (d *Database) CreateGroupPermission(ctx context.Context, tx *sql.Tx, groupPermission *record.GroupPermission) error {

	if groupPermission.GroupID == 0 {
		return errs.New("can't create groupPermission with group_id 0")
	}

	if groupPermission.PermissionID == 0 {
		return errs.New("can't create groupPermission with permission_id 0")
	}

	now := time.Now().UTC()

	originalCreatedAt := groupPermission.CreatedAt
	originalUpdatedAt := groupPermission.UpdatedAt
	groupPermission.CreatedAt = sql.NullTime{Time: now, Valid: true}
	groupPermission.UpdatedAt = sql.NullTime{Time: now, Valid: true}

	id, err := d.insert(ctx, tx, insertGroupPermission, "groupPermission",
		groupPermission.CreatedAt, groupPermission.UpdatedAt, groupPermission.GroupID, groupPermission.PermissionID)
	if err != nil {
		groupPermission.CreatedAt = originalCreatedAt
		groupPermission.UpdatedAt = originalUpdatedAt
		return err
	}

	groupPermission.ID = id
	return nil
}

func (d *Database) UpdateGroupPermission(ctx context.Context, tx *sql.Tx, groupPermission *record.GroupPermission) error {

	if groupPermission.ID == 0 {
		return errs.New("can't update groupPermission with id 0")
	}

	originalUpdatedAt := groupPermission.UpdatedAt
	groupPermission.UpdatedAt = sql.NullTime{Time: time.Now().UTC(), Valid: true}

	_, err := d.ExecSQL(ctx, tx, updateGroupPermission.text(d.Dialect),
		groupPermission.UpdatedAt, groupPermission.GroupID, groupPermission.PermissionID,
		groupPermission.ID)
	if err != nil {
		groupPermission.UpdatedAt = originalUpdatedAt
		return errs.Wrap(err, "unable to update groupPermission")
	}

	return nil
}

func (d *Database) GetGroupPermissionsByGroupID(ctx context.Context, tx *sql.Tx, groupID int64) ([]record.GroupPermission, error) {
	return queryAll(ctx, d, tx, nil, selectGroupPermissionsByGroupID.text(d.Dialect), []any{groupID},
		scanGroupPermission, "groupPermission")
}

func (d *Database) GetGroupPermissionsByGroupIDs(ctx context.Context, tx *sql.Tx, groupIDs []int64) ([]record.GroupPermission, error) {

	if len(groupIDs) == 0 {
		return nil, nil
	}

	var groupPermissions []record.GroupPermission

	err := forEachIDBatch(groupIDs, func(batch []int64) error {
		query := selectGroupPermissionsWhere.text(d.Dialect) + inList(d.Dialect, "group_id", 1, len(batch))
		var err error
		groupPermissions, err = queryAll(ctx, d, tx, groupPermissions, query, int64Args(batch),
			scanGroupPermission, "groupPermission")
		return err
	})
	if err != nil {
		return nil, err
	}

	return groupPermissions, nil
}

func (d *Database) GetGroupPermissionByID(ctx context.Context, tx *sql.Tx, groupPermissionID int64) (*record.GroupPermission, error) {
	return queryOne(ctx, d, tx, selectGroupPermissionByID.text(d.Dialect), []any{groupPermissionID},
		scanGroupPermission, "groupPermission")
}

func (d *Database) GetGroupPermissionByGroupIDAndPermissionID(ctx context.Context, tx *sql.Tx, groupID, permissionID int64) (*record.GroupPermission, error) {
	return queryOne(ctx, d, tx, selectGroupPermissionByGroupIDAndPermissionID.text(d.Dialect),
		[]any{groupID, permissionID}, scanGroupPermission, "groupPermission")
}

func (d *Database) DeleteGroupPermission(ctx context.Context, tx *sql.Tx, groupPermissionID int64) error {

	_, err := d.ExecSQL(ctx, tx, deleteGroupPermission.text(d.Dialect), groupPermissionID)
	if err != nil {
		return errs.Wrap(err, "unable to delete groupPermission")
	}

	return nil
}
