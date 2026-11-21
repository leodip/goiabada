package commondb

import (
	"context"
	"database/sql"
	"time"

	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/errs"
)

// userGroupColumns is the users_groups table as scanUserGroup reads it.
var userGroupColumns = columnList{
	sqlite:   "id, created_at, updated_at, user_id, group_id",
	mysql:    "id, created_at, updated_at, user_id, group_id",
	postgres: "id, created_at, updated_at, user_id, group_id",
	mssql:    "id, created_at, updated_at, user_id, group_id",
}

// scanUserGroup reads one row selected with userGroupColumns.
func scanUserGroup(row rowScanner, userGroup *record.UserGroup) error {
	return row.Scan(
		&userGroup.ID,
		&userGroup.CreatedAt,
		&userGroup.UpdatedAt,
		&userGroup.UserID,
		&userGroup.GroupID,
	)
}

var insertUserGroup = statement{
	sqlite:   "INSERT INTO users_groups (created_at, updated_at, user_id, group_id) VALUES (?, ?, ?, ?)",
	mysql:    "INSERT INTO users_groups (created_at, updated_at, user_id, group_id) VALUES (?, ?, ?, ?)",
	postgres: "INSERT INTO users_groups (created_at, updated_at, user_id, group_id) VALUES ($1, $2, $3, $4) RETURNING id",
	mssql:    "INSERT INTO users_groups (created_at, updated_at, user_id, group_id) OUTPUT INSERTED.id VALUES (@p1, @p2, @p3, @p4)",
}

// updateUserGroup writes the whole row but created_at, which is dont-update.
var updateUserGroup = statement{
	sqlite:   "UPDATE users_groups SET updated_at = ?, user_id = ?, group_id = ? WHERE id = ?",
	mysql:    "UPDATE users_groups SET updated_at = ?, user_id = ?, group_id = ? WHERE id = ?",
	postgres: "UPDATE users_groups SET updated_at = $1, user_id = $2, group_id = $3 WHERE id = $4",
	mssql:    "UPDATE users_groups SET updated_at = @p1, user_id = @p2, group_id = @p3 WHERE id = @p4",
}

var selectUserGroupByID = statement{
	sqlite:   "SELECT " + userGroupColumns.sqlite + " FROM users_groups WHERE id = ?",
	mysql:    "SELECT " + userGroupColumns.mysql + " FROM users_groups WHERE id = ?",
	postgres: "SELECT " + userGroupColumns.postgres + " FROM users_groups WHERE id = $1",
	mssql:    "SELECT " + userGroupColumns.mssql + " FROM users_groups WHERE id = @p1",
}

var selectUserGroupByUserIDAndGroupID = statement{
	sqlite:   "SELECT " + userGroupColumns.sqlite + " FROM users_groups WHERE user_id = ? AND group_id = ?",
	mysql:    "SELECT " + userGroupColumns.mysql + " FROM users_groups WHERE user_id = ? AND group_id = ?",
	postgres: "SELECT " + userGroupColumns.postgres + " FROM users_groups WHERE user_id = $1 AND group_id = $2",
	mssql:    "SELECT " + userGroupColumns.mssql + " FROM users_groups WHERE user_id = @p1 AND group_id = @p2",
}

var selectUserGroupsByUserID = statement{
	sqlite:   "SELECT " + userGroupColumns.sqlite + " FROM users_groups WHERE user_id = ?",
	mysql:    "SELECT " + userGroupColumns.mysql + " FROM users_groups WHERE user_id = ?",
	postgres: "SELECT " + userGroupColumns.postgres + " FROM users_groups WHERE user_id = $1",
	mssql:    "SELECT " + userGroupColumns.mssql + " FROM users_groups WHERE user_id = @p1",
}

// selectUserGroupsWhere is completed by an IN list of user ids.
var selectUserGroupsWhere = statement{
	sqlite:   "SELECT " + userGroupColumns.sqlite + " FROM users_groups WHERE ",
	mysql:    "SELECT " + userGroupColumns.mysql + " FROM users_groups WHERE ",
	postgres: "SELECT " + userGroupColumns.postgres + " FROM users_groups WHERE ",
	mssql:    "SELECT " + userGroupColumns.mssql + " FROM users_groups WHERE ",
}

var deleteUserGroup = statement{
	sqlite:   "DELETE FROM users_groups WHERE id = ?",
	mysql:    "DELETE FROM users_groups WHERE id = ?",
	postgres: "DELETE FROM users_groups WHERE id = $1",
	mssql:    "DELETE FROM users_groups WHERE id = @p1",
}

func (d *Database) CreateUserGroup(ctx context.Context, tx *sql.Tx, userGroup *record.UserGroup) error {

	if userGroup.UserID == 0 {
		return errs.New("can't create userGroup with user_id 0")
	}

	if userGroup.GroupID == 0 {
		return errs.New("can't create userGroup with group_id 0")
	}

	now := time.Now().UTC()

	originalCreatedAt := userGroup.CreatedAt
	originalUpdatedAt := userGroup.UpdatedAt
	userGroup.CreatedAt = sql.NullTime{Time: now, Valid: true}
	userGroup.UpdatedAt = sql.NullTime{Time: now, Valid: true}

	id, err := d.insert(ctx, tx, insertUserGroup, "userGroup",
		userGroup.CreatedAt, userGroup.UpdatedAt, userGroup.UserID, userGroup.GroupID)
	if err != nil {
		userGroup.CreatedAt = originalCreatedAt
		userGroup.UpdatedAt = originalUpdatedAt
		return err
	}

	userGroup.ID = id
	return nil
}

func (d *Database) UpdateUserGroup(ctx context.Context, tx *sql.Tx, userGroup *record.UserGroup) error {

	if userGroup.ID == 0 {
		return errs.New("can't update userGroup with id 0")
	}

	originalUpdatedAt := userGroup.UpdatedAt
	userGroup.UpdatedAt = sql.NullTime{Time: time.Now().UTC(), Valid: true}

	_, err := d.ExecSQL(ctx, tx, updateUserGroup.text(d.Dialect),
		userGroup.UpdatedAt, userGroup.UserID, userGroup.GroupID,
		userGroup.ID)
	if err != nil {
		userGroup.UpdatedAt = originalUpdatedAt
		return errs.Wrap(err, "unable to update userGroup")
	}

	return nil
}

func (d *Database) GetUserGroupByID(ctx context.Context, tx *sql.Tx, userGroupID int64) (*record.UserGroup, error) {
	return queryOne(ctx, d, tx, selectUserGroupByID.text(d.Dialect), []any{userGroupID}, scanUserGroup, "userGroup")
}

func (d *Database) GetUserGroupsByUserIDs(ctx context.Context, tx *sql.Tx, userIDs []int64) ([]record.UserGroup, error) {

	if len(userIDs) == 0 {
		return nil, nil
	}

	var userGroups []record.UserGroup

	err := forEachIDBatch(userIDs, func(batch []int64) error {
		query := selectUserGroupsWhere.text(d.Dialect) + inList(d.Dialect, "user_id", 1, len(batch))
		var err error
		userGroups, err = queryAll(ctx, d, tx, userGroups, query, int64Args(batch), scanUserGroup, "userGroup")
		return err
	})
	if err != nil {
		return nil, err
	}

	return userGroups, nil
}

func (d *Database) GetUserGroupsByUserID(ctx context.Context, tx *sql.Tx, userID int64) ([]record.UserGroup, error) {
	return queryAll(ctx, d, tx, nil, selectUserGroupsByUserID.text(d.Dialect), []any{userID}, scanUserGroup, "userGroup")
}

func (d *Database) GetUserGroupByUserIDAndGroupID(ctx context.Context, tx *sql.Tx, userID, groupID int64) (*record.UserGroup, error) {
	return queryOne(ctx, d, tx, selectUserGroupByUserIDAndGroupID.text(d.Dialect), []any{userID, groupID},
		scanUserGroup, "userGroup")
}

func (d *Database) DeleteUserGroup(ctx context.Context, tx *sql.Tx, userGroupID int64) error {

	_, err := d.ExecSQL(ctx, tx, deleteUserGroup.text(d.Dialect), userGroupID)
	if err != nil {
		return errs.Wrap(err, "unable to delete userGroup")
	}

	return nil
}
