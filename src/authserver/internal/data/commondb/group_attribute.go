package commondb

import (
	"context"
	"database/sql"
	"time"

	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/errs"
)

// groupAttributeColumns is the group_attributes table as scanGroupAttribute reads it. key and
// value are reserved words, quoted with backticks on MySQL and double quotes on the other three.
var groupAttributeColumns = columnList{
	sqlite:   `id, created_at, updated_at, "key", "value", include_in_id_token, include_in_access_token, group_id`,
	mysql:    "id, created_at, updated_at, `key`, `value`, include_in_id_token, include_in_access_token, group_id",
	postgres: `id, created_at, updated_at, "key", "value", include_in_id_token, include_in_access_token, group_id`,
	mssql:    `id, created_at, updated_at, "key", "value", include_in_id_token, include_in_access_token, group_id`,
}

// scanGroupAttribute reads one row selected with groupAttributeColumns.
func scanGroupAttribute(row rowScanner, groupAttribute *record.GroupAttribute) error {
	return row.Scan(
		&groupAttribute.Id,
		&groupAttribute.CreatedAt,
		&groupAttribute.UpdatedAt,
		&groupAttribute.Key,
		&groupAttribute.Value,
		&groupAttribute.IncludeInIdToken,
		&groupAttribute.IncludeInAccessToken,
		&groupAttribute.GroupId,
	)
}

var insertGroupAttribute = statement{
	sqlite: `INSERT INTO group_attributes (created_at, updated_at, "key", "value", include_in_id_token, include_in_access_token, group_id) ` +
		`VALUES (?, ?, ?, ?, ?, ?, ?)`,
	mysql: "INSERT INTO group_attributes (created_at, updated_at, `key`, `value`, include_in_id_token, include_in_access_token, group_id) " +
		"VALUES (?, ?, ?, ?, ?, ?, ?)",
	postgres: `INSERT INTO group_attributes (created_at, updated_at, "key", "value", include_in_id_token, include_in_access_token, group_id) ` +
		`VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id`,
	mssql: `INSERT INTO group_attributes (created_at, updated_at, "key", "value", include_in_id_token, include_in_access_token, group_id) ` +
		`OUTPUT INSERTED.id VALUES (@p1, @p2, @p3, @p4, @p5, @p6, @p7)`,
}

// updateGroupAttribute writes the whole row but created_at, which is dont-update.
var updateGroupAttribute = statement{
	sqlite: `UPDATE group_attributes SET updated_at = ?, "key" = ?, "value" = ?, include_in_id_token = ?, ` +
		`include_in_access_token = ?, group_id = ? WHERE id = ?`,
	mysql: "UPDATE group_attributes SET updated_at = ?, `key` = ?, `value` = ?, include_in_id_token = ?, " +
		"include_in_access_token = ?, group_id = ? WHERE id = ?",
	postgres: `UPDATE group_attributes SET updated_at = $1, "key" = $2, "value" = $3, include_in_id_token = $4, ` +
		`include_in_access_token = $5, group_id = $6 WHERE id = $7`,
	mssql: `UPDATE group_attributes SET updated_at = @p1, "key" = @p2, "value" = @p3, include_in_id_token = @p4, ` +
		`include_in_access_token = @p5, group_id = @p6 WHERE id = @p7`,
}

var selectGroupAttributeById = statement{
	sqlite:   "SELECT " + groupAttributeColumns.sqlite + " FROM group_attributes WHERE id = ?",
	mysql:    "SELECT " + groupAttributeColumns.mysql + " FROM group_attributes WHERE id = ?",
	postgres: "SELECT " + groupAttributeColumns.postgres + " FROM group_attributes WHERE id = $1",
	mssql:    "SELECT " + groupAttributeColumns.mssql + " FROM group_attributes WHERE id = @p1",
}

var selectGroupAttributesByGroupId = statement{
	sqlite:   "SELECT " + groupAttributeColumns.sqlite + " FROM group_attributes WHERE group_id = ?",
	mysql:    "SELECT " + groupAttributeColumns.mysql + " FROM group_attributes WHERE group_id = ?",
	postgres: "SELECT " + groupAttributeColumns.postgres + " FROM group_attributes WHERE group_id = $1",
	mssql:    "SELECT " + groupAttributeColumns.mssql + " FROM group_attributes WHERE group_id = @p1",
}

// selectGroupAttributesWhere is completed by an IN list of group ids.
var selectGroupAttributesWhere = statement{
	sqlite:   "SELECT " + groupAttributeColumns.sqlite + " FROM group_attributes WHERE ",
	mysql:    "SELECT " + groupAttributeColumns.mysql + " FROM group_attributes WHERE ",
	postgres: "SELECT " + groupAttributeColumns.postgres + " FROM group_attributes WHERE ",
	mssql:    "SELECT " + groupAttributeColumns.mssql + " FROM group_attributes WHERE ",
}

var deleteGroupAttribute = statement{
	sqlite:   "DELETE FROM group_attributes WHERE id = ?",
	mysql:    "DELETE FROM group_attributes WHERE id = ?",
	postgres: "DELETE FROM group_attributes WHERE id = $1",
	mssql:    "DELETE FROM group_attributes WHERE id = @p1",
}

func (d *Database) CreateGroupAttribute(ctx context.Context, tx *sql.Tx, groupAttribute *record.GroupAttribute) error {

	if groupAttribute.GroupId == 0 {
		return errs.New("can't create groupAttribute with group_id 0")
	}

	now := time.Now().UTC()

	originalCreatedAt := groupAttribute.CreatedAt
	originalUpdatedAt := groupAttribute.UpdatedAt
	groupAttribute.CreatedAt = sql.NullTime{Time: now, Valid: true}
	groupAttribute.UpdatedAt = sql.NullTime{Time: now, Valid: true}

	id, err := d.insert(ctx, tx, insertGroupAttribute, "groupAttribute",
		groupAttribute.CreatedAt, groupAttribute.UpdatedAt, groupAttribute.Key, groupAttribute.Value,
		groupAttribute.IncludeInIdToken, groupAttribute.IncludeInAccessToken, groupAttribute.GroupId)
	if err != nil {
		groupAttribute.CreatedAt = originalCreatedAt
		groupAttribute.UpdatedAt = originalUpdatedAt
		return err
	}

	groupAttribute.Id = id
	return nil
}

func (d *Database) UpdateGroupAttribute(ctx context.Context, tx *sql.Tx, groupAttribute *record.GroupAttribute) error {

	if groupAttribute.Id == 0 {
		return errs.New("can't update groupAttribute with id 0")
	}

	originalUpdatedAt := groupAttribute.UpdatedAt
	groupAttribute.UpdatedAt = sql.NullTime{Time: time.Now().UTC(), Valid: true}

	_, err := d.ExecSQL(ctx, tx, updateGroupAttribute.text(d.Dialect),
		groupAttribute.UpdatedAt, groupAttribute.Key, groupAttribute.Value, groupAttribute.IncludeInIdToken,
		groupAttribute.IncludeInAccessToken, groupAttribute.GroupId,
		groupAttribute.Id)
	if err != nil {
		groupAttribute.UpdatedAt = originalUpdatedAt
		return errs.Wrap(err, "unable to update groupAttribute")
	}

	return nil
}

func (d *Database) GetGroupAttributeById(ctx context.Context, tx *sql.Tx, groupAttributeId int64) (*record.GroupAttribute, error) {
	return queryOne(ctx, d, tx, selectGroupAttributeById.text(d.Dialect), []any{groupAttributeId},
		scanGroupAttribute, "groupAttribute")
}

func (d *Database) GetGroupAttributesByGroupIds(ctx context.Context, tx *sql.Tx, groupIds []int64) ([]record.GroupAttribute, error) {

	if len(groupIds) == 0 {
		return nil, nil
	}

	var groupAttributes []record.GroupAttribute

	err := forEachIdBatch(groupIds, func(batch []int64) error {
		query := selectGroupAttributesWhere.text(d.Dialect) + inList(d.Dialect, "group_id", 1, len(batch))
		var err error
		groupAttributes, err = queryAll(ctx, d, tx, groupAttributes, query, int64Args(batch),
			scanGroupAttribute, "groupAttribute")
		return err
	})
	if err != nil {
		return nil, err
	}

	return groupAttributes, nil
}

func (d *Database) GetGroupAttributesByGroupId(ctx context.Context, tx *sql.Tx, groupId int64) ([]record.GroupAttribute, error) {
	return queryAll(ctx, d, tx, nil, selectGroupAttributesByGroupId.text(d.Dialect), []any{groupId},
		scanGroupAttribute, "groupAttribute")
}

func (d *Database) DeleteGroupAttribute(ctx context.Context, tx *sql.Tx, groupAttributeId int64) error {

	_, err := d.ExecSQL(ctx, tx, deleteGroupAttribute.text(d.Dialect), groupAttributeId)
	if err != nil {
		return errs.Wrap(err, "unable to delete groupAttribute")
	}

	return nil
}
