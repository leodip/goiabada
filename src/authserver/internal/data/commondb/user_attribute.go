package commondb

import (
	"context"
	"database/sql"
	"time"

	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/errs"
)

// userAttributeColumns is the user_attributes table as scanUserAttribute reads it. key and value
// are reserved words, quoted with backticks on MySQL and double quotes on the other three.
var userAttributeColumns = columnList{
	sqlite:   `id, created_at, updated_at, "key", "value", include_in_id_token, include_in_access_token, user_id`,
	mysql:    "id, created_at, updated_at, `key`, `value`, include_in_id_token, include_in_access_token, user_id",
	postgres: `id, created_at, updated_at, "key", "value", include_in_id_token, include_in_access_token, user_id`,
	mssql:    `id, created_at, updated_at, "key", "value", include_in_id_token, include_in_access_token, user_id`,
}

// scanUserAttribute reads one row selected with userAttributeColumns.
func scanUserAttribute(row rowScanner, userAttribute *record.UserAttribute) error {
	return row.Scan(
		&userAttribute.Id,
		&userAttribute.CreatedAt,
		&userAttribute.UpdatedAt,
		&userAttribute.Key,
		&userAttribute.Value,
		&userAttribute.IncludeInIdToken,
		&userAttribute.IncludeInAccessToken,
		&userAttribute.UserId,
	)
}

var insertUserAttribute = statement{
	sqlite: `INSERT INTO user_attributes (created_at, updated_at, "key", "value", include_in_id_token, include_in_access_token, user_id) ` +
		`VALUES (?, ?, ?, ?, ?, ?, ?)`,
	mysql: "INSERT INTO user_attributes (created_at, updated_at, `key`, `value`, include_in_id_token, include_in_access_token, user_id) " +
		"VALUES (?, ?, ?, ?, ?, ?, ?)",
	postgres: `INSERT INTO user_attributes (created_at, updated_at, "key", "value", include_in_id_token, include_in_access_token, user_id) ` +
		`VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id`,
	mssql: `INSERT INTO user_attributes (created_at, updated_at, "key", "value", include_in_id_token, include_in_access_token, user_id) ` +
		`OUTPUT INSERTED.id VALUES (@p1, @p2, @p3, @p4, @p5, @p6, @p7)`,
}

// updateUserAttribute writes the whole row but created_at, which is dont-update.
var updateUserAttribute = statement{
	sqlite: `UPDATE user_attributes SET updated_at = ?, "key" = ?, "value" = ?, include_in_id_token = ?, ` +
		`include_in_access_token = ?, user_id = ? WHERE id = ?`,
	mysql: "UPDATE user_attributes SET updated_at = ?, `key` = ?, `value` = ?, include_in_id_token = ?, " +
		"include_in_access_token = ?, user_id = ? WHERE id = ?",
	postgres: `UPDATE user_attributes SET updated_at = $1, "key" = $2, "value" = $3, include_in_id_token = $4, ` +
		`include_in_access_token = $5, user_id = $6 WHERE id = $7`,
	mssql: `UPDATE user_attributes SET updated_at = @p1, "key" = @p2, "value" = @p3, include_in_id_token = @p4, ` +
		`include_in_access_token = @p5, user_id = @p6 WHERE id = @p7`,
}

var selectUserAttributeById = statement{
	sqlite:   "SELECT " + userAttributeColumns.sqlite + " FROM user_attributes WHERE id = ?",
	mysql:    "SELECT " + userAttributeColumns.mysql + " FROM user_attributes WHERE id = ?",
	postgres: "SELECT " + userAttributeColumns.postgres + " FROM user_attributes WHERE id = $1",
	mssql:    "SELECT " + userAttributeColumns.mssql + " FROM user_attributes WHERE id = @p1",
}

var selectUserAttributesByUserId = statement{
	sqlite:   "SELECT " + userAttributeColumns.sqlite + " FROM user_attributes WHERE user_id = ?",
	mysql:    "SELECT " + userAttributeColumns.mysql + " FROM user_attributes WHERE user_id = ?",
	postgres: "SELECT " + userAttributeColumns.postgres + " FROM user_attributes WHERE user_id = $1",
	mssql:    "SELECT " + userAttributeColumns.mssql + " FROM user_attributes WHERE user_id = @p1",
}

var deleteUserAttribute = statement{
	sqlite:   "DELETE FROM user_attributes WHERE id = ?",
	mysql:    "DELETE FROM user_attributes WHERE id = ?",
	postgres: "DELETE FROM user_attributes WHERE id = $1",
	mssql:    "DELETE FROM user_attributes WHERE id = @p1",
}

func (d *Database) CreateUserAttribute(ctx context.Context, tx *sql.Tx, userAttribute *record.UserAttribute) error {

	if userAttribute.UserId == 0 {
		return errs.New("can't create userAttribute with user_id 0")
	}

	now := time.Now().UTC()

	originalCreatedAt := userAttribute.CreatedAt
	originalUpdatedAt := userAttribute.UpdatedAt
	userAttribute.CreatedAt = sql.NullTime{Time: now, Valid: true}
	userAttribute.UpdatedAt = sql.NullTime{Time: now, Valid: true}

	id, err := d.insert(ctx, tx, insertUserAttribute, "userAttribute",
		userAttribute.CreatedAt, userAttribute.UpdatedAt, userAttribute.Key, userAttribute.Value,
		userAttribute.IncludeInIdToken, userAttribute.IncludeInAccessToken, userAttribute.UserId)
	if err != nil {
		userAttribute.CreatedAt = originalCreatedAt
		userAttribute.UpdatedAt = originalUpdatedAt
		return err
	}

	userAttribute.Id = id
	return nil
}

func (d *Database) UpdateUserAttribute(ctx context.Context, tx *sql.Tx, userAttribute *record.UserAttribute) error {

	if userAttribute.Id == 0 {
		return errs.New("can't update userAttribute with id 0")
	}

	originalUpdatedAt := userAttribute.UpdatedAt
	userAttribute.UpdatedAt = sql.NullTime{Time: time.Now().UTC(), Valid: true}

	_, err := d.ExecSQL(ctx, tx, updateUserAttribute.text(d.Dialect),
		userAttribute.UpdatedAt, userAttribute.Key, userAttribute.Value, userAttribute.IncludeInIdToken,
		userAttribute.IncludeInAccessToken, userAttribute.UserId,
		userAttribute.Id)
	if err != nil {
		userAttribute.UpdatedAt = originalUpdatedAt
		return errs.Wrap(err, "unable to update userAttribute")
	}

	return nil
}

func (d *Database) GetUserAttributeById(ctx context.Context, tx *sql.Tx, userAttributeId int64) (*record.UserAttribute, error) {
	return queryOne(ctx, d, tx, selectUserAttributeById.text(d.Dialect), []any{userAttributeId},
		scanUserAttribute, "userAttribute")
}

func (d *Database) GetUserAttributesByUserId(ctx context.Context, tx *sql.Tx, userId int64) ([]record.UserAttribute, error) {
	return queryAll(ctx, d, tx, nil, selectUserAttributesByUserId.text(d.Dialect), []any{userId},
		scanUserAttribute, "userAttribute")
}

func (d *Database) DeleteUserAttribute(ctx context.Context, tx *sql.Tx, userAttributeId int64) error {

	_, err := d.ExecSQL(ctx, tx, deleteUserAttribute.text(d.Dialect), userAttributeId)
	if err != nil {
		return errs.Wrap(err, "unable to delete userAttribute")
	}

	return nil
}
