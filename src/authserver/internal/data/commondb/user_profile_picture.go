package commondb

import (
	"context"
	"database/sql"
	"time"

	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/errs"
)

// userProfilePictureColumns is the user_profile_pictures table as scanUserProfilePicture reads it.
var userProfilePictureColumns = columnList{
	sqlite:   "id, created_at, updated_at, user_id, picture, content_type",
	mysql:    "id, created_at, updated_at, user_id, picture, content_type",
	postgres: "id, created_at, updated_at, user_id, picture, content_type",
	mssql:    "id, created_at, updated_at, user_id, picture, content_type",
}

// scanUserProfilePicture reads one row selected with userProfilePictureColumns.
func scanUserProfilePicture(row rowScanner, profilePicture *record.UserProfilePicture) error {
	return row.Scan(
		&profilePicture.Id,
		&profilePicture.CreatedAt,
		&profilePicture.UpdatedAt,
		&profilePicture.UserId,
		&profilePicture.Picture,
		&profilePicture.ContentType,
	)
}

var insertUserProfilePicture = statement{
	sqlite:   "INSERT INTO user_profile_pictures (created_at, updated_at, user_id, picture, content_type) VALUES (?, ?, ?, ?, ?)",
	mysql:    "INSERT INTO user_profile_pictures (created_at, updated_at, user_id, picture, content_type) VALUES (?, ?, ?, ?, ?)",
	postgres: "INSERT INTO user_profile_pictures (created_at, updated_at, user_id, picture, content_type) VALUES ($1, $2, $3, $4, $5) RETURNING id",
	mssql:    "INSERT INTO user_profile_pictures (created_at, updated_at, user_id, picture, content_type) OUTPUT INSERTED.id VALUES (@p1, @p2, @p3, @p4, @p5)",
}

// updateUserProfilePicture writes the whole row but created_at, which is dont-update.
var updateUserProfilePicture = statement{
	sqlite:   "UPDATE user_profile_pictures SET updated_at = ?, user_id = ?, picture = ?, content_type = ? WHERE id = ?",
	mysql:    "UPDATE user_profile_pictures SET updated_at = ?, user_id = ?, picture = ?, content_type = ? WHERE id = ?",
	postgres: "UPDATE user_profile_pictures SET updated_at = $1, user_id = $2, picture = $3, content_type = $4 WHERE id = $5",
	mssql:    "UPDATE user_profile_pictures SET updated_at = @p1, user_id = @p2, picture = @p3, content_type = @p4 WHERE id = @p5",
}

var selectUserProfilePictureByUserId = statement{
	sqlite:   "SELECT " + userProfilePictureColumns.sqlite + " FROM user_profile_pictures WHERE user_id = ?",
	mysql:    "SELECT " + userProfilePictureColumns.mysql + " FROM user_profile_pictures WHERE user_id = ?",
	postgres: "SELECT " + userProfilePictureColumns.postgres + " FROM user_profile_pictures WHERE user_id = $1",
	mssql:    "SELECT " + userProfilePictureColumns.mssql + " FROM user_profile_pictures WHERE user_id = @p1",
}

var deleteUserProfilePicture = statement{
	sqlite:   "DELETE FROM user_profile_pictures WHERE user_id = ?",
	mysql:    "DELETE FROM user_profile_pictures WHERE user_id = ?",
	postgres: "DELETE FROM user_profile_pictures WHERE user_id = $1",
	mssql:    "DELETE FROM user_profile_pictures WHERE user_id = @p1",
}

// selectUserHasProfilePicture reads at most one row. SQL Server pages with OFFSET … FETCH, which it
// accepts only after an ORDER BY.
var selectUserHasProfilePicture = statement{
	sqlite:   "SELECT 1 FROM user_profile_pictures WHERE user_id = ? LIMIT 1",
	mysql:    "SELECT 1 FROM user_profile_pictures WHERE user_id = ? LIMIT 1",
	postgres: "SELECT 1 FROM user_profile_pictures WHERE user_id = $1 LIMIT 1",
	mssql:    "SELECT 1 FROM user_profile_pictures WHERE user_id = @p1 ORDER BY 1 OFFSET 0 ROWS FETCH NEXT 1 ROWS ONLY",
}

func (d *Database) CreateUserProfilePicture(ctx context.Context, tx *sql.Tx, profilePicture *record.UserProfilePicture) error {

	if profilePicture.UserId == 0 {
		return errs.New("can't create profile picture with user_id 0")
	}

	now := time.Now().UTC()

	originalCreatedAt := profilePicture.CreatedAt
	originalUpdatedAt := profilePicture.UpdatedAt
	profilePicture.CreatedAt = sql.NullTime{Time: now, Valid: true}
	profilePicture.UpdatedAt = sql.NullTime{Time: now, Valid: true}

	id, err := d.insert(ctx, tx, insertUserProfilePicture, "profile picture",
		profilePicture.CreatedAt, profilePicture.UpdatedAt, profilePicture.UserId, profilePicture.Picture,
		profilePicture.ContentType)
	if err != nil {
		profilePicture.CreatedAt = originalCreatedAt
		profilePicture.UpdatedAt = originalUpdatedAt
		return err
	}

	profilePicture.Id = id
	return nil
}

func (d *Database) UpdateUserProfilePicture(ctx context.Context, tx *sql.Tx, profilePicture *record.UserProfilePicture) error {

	if profilePicture.Id == 0 {
		return errs.New("can't update profile picture with id 0")
	}

	originalUpdatedAt := profilePicture.UpdatedAt
	profilePicture.UpdatedAt = sql.NullTime{Time: time.Now().UTC(), Valid: true}

	_, err := d.ExecSQL(ctx, tx, updateUserProfilePicture.text(d.Dialect),
		profilePicture.UpdatedAt, profilePicture.UserId, profilePicture.Picture, profilePicture.ContentType,
		profilePicture.Id)
	if err != nil {
		profilePicture.UpdatedAt = originalUpdatedAt
		return errs.Wrap(err, "unable to update profile picture")
	}

	return nil
}

func (d *Database) GetUserProfilePictureByUserId(ctx context.Context, tx *sql.Tx, userId int64) (*record.UserProfilePicture, error) {
	return queryOne(ctx, d, tx, selectUserProfilePictureByUserId.text(d.Dialect), []any{userId},
		scanUserProfilePicture, "profile picture")
}

func (d *Database) DeleteUserProfilePicture(ctx context.Context, tx *sql.Tx, userId int64) error {

	_, err := d.ExecSQL(ctx, tx, deleteUserProfilePicture.text(d.Dialect), userId)
	if err != nil {
		return errs.Wrap(err, "unable to delete profile picture")
	}

	return nil
}

func (d *Database) UserHasProfilePicture(ctx context.Context, tx *sql.Tx, userId int64) (bool, error) {

	rows, err := d.QuerySQL(ctx, tx, selectUserHasProfilePicture.text(d.Dialect), userId)
	if err != nil {
		return false, errs.Wrap(err, "unable to query database")
	}
	defer func() { _ = rows.Close() }()

	exists := rows.Next()
	if err := rows.Err(); err != nil {
		return false, errs.Wrap(err, "unable to read query results")
	}

	return exists, nil
}
